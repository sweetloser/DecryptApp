//
//  DecryptApp.mm
//  DecryptApp
//
//  Created by 曾祥翔 on 2017/11/10.
//  Copyright (c) 2017年 ___ORGANIZATIONNAME___. All rights reserved.
//

// CaptainHook by Ryan Petrich
// see https://github.com/rpetrich/CaptainHook/

#import <Foundation/Foundation.h>
#import "CaptainHook/CaptainHook.h"



#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <fcntl.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>


__attribute__((constructor)) static void entey(){
    printf("i will decript you.\n");
    int count = _dyld_image_count();
    printf("count:%d.\n",count);
    const char *bundle_path = [[[NSBundle mainBundle] bundlePath] UTF8String];
    for (int i=0; i<count; i++) {
        const char *imagename = _dyld_get_image_name(i);
        if (strstr(imagename, bundle_path) != NULL) {
            printf("image_name:%s.\n",imagename);
            
            struct load_command *lc;
            struct encryption_info_command *eic;
            struct fat_header *fh;
            struct fat_arch *arch;
            char buffer[1024];
            char rpath[4096],npath[4096];
            unsigned long fileoffs = 0,off_cryptid = 0,restsize;
            
            
            const struct mach_header *sub_mh = _dyld_get_image_header(i);
            if (sub_mh->magic == MH_MAGIC_64) {
                lc = (struct load_command *)((unsigned char *)sub_mh + sizeof(struct mach_header_64));
                printf("[+] detected 64bit ARM binary in memory..\n");
            }else{
                lc = (struct load_command *)((unsigned char *)sub_mh + sizeof(struct mach_header));
                printf("[+] detected 32bit ARM binary in memory..\n");
            }
            printf("ncmds:%d.\n",sub_mh->ncmds);
            for (int i=0; i<sub_mh->ncmds; i++) {
                if (lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {
                    printf("encrypt load_command:%d.\n",i);
                    eic = (struct encryption_info_command *)lc;
                    if (eic->cryptid == 0) {
                        printf("is not encrypt.\n");
                        break;
                    }
                    //获取cryptid在什么位置（解密之后要修改cryptid的值为0）
                    off_cryptid = (unsigned long)((unsigned long)&eic->cryptid - (unsigned long)sub_mh);
                    printf("[+] offset to cryptid found:%p(from %p) = %lx.\n",&eic->cryptid,sub_mh,off_cryptid);
                    printf("[+] found encrypt data at address %08x of length %u bytes - type %u.\n",eic->cryptoff, eic->cryptsize, eic->cryptid);
                    strlcpy(rpath, imagename, sizeof(rpath));
                    int fd = open(rpath, O_RDONLY);
                    if (fd == -1) {
                        printf("[-] failed opening.\n");
                        _exit(1);
                    }
                    printf("[+] Reading header\n");
                    
                    long n = read(fd, (void *)buffer,sizeof(buffer));
                    if (n != sizeof(buffer)) {
                        printf("[W] Warning read only %ld bytes\n", n);
                    }
                    printf("[+] Detecting header type\n");
                    fh = (struct fat_header *)buffer;
                    if (fh->magic == FAT_CIGAM) {
                        printf("[+] Executable is a FAT image - searching for right architecture\n");
                        arch = (struct fat_arch *)&fh[1];
                        for (int i=0; i<CFSwapInt32(fh->nfat_arch); i++) {
                            if ((sub_mh->cputype == CFSwapInt32(arch->cputype)) && (sub_mh->cpusubtype == CFSwapInt32(arch->cpusubtype))) {
                                fileoffs = CFSwapInt32(arch->offset);
                                printf("[+] Correct arch is at offset %lu in the file\n", fileoffs);
                                break;
                            }
                            arch++;
                        }
                        if (fileoffs == 0) {
                            printf("[-] Could not find correct arch in FAT image\n");
                            _exit(1);
                        }
                    }else if (fh->magic == MH_MAGIC || fh->magic == MH_MAGIC_64){
                        printf("[+] Executable is a plain MACH-O image\n");
                    }else{
                        printf("[-] Executable is of unknown type\n");
                        _exit(1);
                    }
                    char *tmp = strrchr(rpath, '/');
                    if (tmp == NULL) {
                        printf("[-] Unexpected error whih filename");
                        _exit(1);
                    }
                    //获取沙河目录，进行写入操作
                    NSString *documentPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
                    strlcpy(npath, [documentPath UTF8String], sizeof(npath));
                    strlcat(npath, tmp, sizeof(npath));
                    strlcat(npath, ".decrypted", sizeof(npath));
                    printf("npath : %s.\n",npath);
                    
                    int outfd = open(npath, O_RDWR | O_CREAT , 0644);
                    unsigned long cryptoff_fileoff = fileoffs + eic->cryptoff;
                    restsize = lseek(fd, 0, SEEK_END) - cryptoff_fileoff - eic->cryptsize;
                    lseek(fd, 0, SEEK_SET);
                    unsigned long toread,r;
                    while (cryptoff_fileoff > 0) {
                        toread = (cryptoff_fileoff>sizeof(buffer))?sizeof(buffer):cryptoff_fileoff;
                        r = read(fd ,buffer, toread);
                        if (r!=toread) {
                            printf("[-] error reading file\n");
                            _exit(1);
                        }
                        cryptoff_fileoff = cryptoff_fileoff-r;
                        
                        r = write(outfd, buffer, toread);
                        if (r != toread) {
                            printf("[-] error writing file\n");
                            _exit(1);
                        }
                    }
                    
                    printf("[+] Dumping the decrypted data into the file\n");
                    r = write(outfd, (unsigned char *)sub_mh + eic->cryptoff, eic->cryptsize);
                    if (r != eic->cryptsize) {
                        printf("[-] Error writing file\n");
                        _exit(1);
                    }
                    lseek(fd, eic->cryptsize, SEEK_CUR);
                    printf("[+] Copying the not encrypted remainder of the file\n");
                    while (restsize>0) {
                        toread = (restsize > sizeof(buffer)) ? sizeof(buffer) : restsize;
                        r = read(fd, buffer, toread);
                        if (r != toread) {
                            printf("[-] Error reading file\n");
                            _exit(1);
                        }
                        restsize -= r;
                        
                        r = write(outfd, buffer, toread);
                        if (r != toread) {
                            printf("[-] Error writing file\n");
                            _exit(1);
                        }
                    }
                    if (off_cryptid) {
                        uint32_t zero = 0;
                        off_cryptid = off_cryptid+fileoffs;
                        printf("[+] Setting the LC_ENCRYPTION_INFO->cryptid to 0 at offset %lx\n", off_cryptid);
                        if (lseek(outfd, off_cryptid, SEEK_SET)!=off_cryptid || write(outfd, &zero, 4) != 4) {
                            printf("[-] Error writing cryptid value\n");
                        }
                    }
                    printf("[+] Closing original file\n");
                    close(fd);
                    printf("[+] Closing dump file\n");
                    close(outfd);
                }
                lc = (struct load_command *)((unsigned char *)lc+lc->cmdsize);
            }
        }
    }
}








