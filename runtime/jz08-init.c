/* SPDX-License-Identifier: GPL-2.0-only
 * External full OpenWrt initramfs entry. No filesystem on eMMC is mounted.
 */
#define _GNU_SOURCE
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <linux/reboot.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/wait.h>

static int module(char *const argv[]) {
    pid_t child=fork();int status;
    if(child<0)return -1;
    if(child==0){execv("/sbin/modprobe",argv);_exit(127);}
    if(waitpid(child,&status,0)<0)return -1;
    return WIFEXITED(status)?WEXITSTATUS(status):-1;
}
static int early_usb(const char *nonce) {
    const char *names[]={"libcomposite","u_ether","usb_f_ecm","usb_f_ecm_subset","usb_f_rndis"};
    for(unsigned int i=0;i<sizeof(names)/sizeof(names[0]);i++) {
        char *args[]={"modprobe",(char *)names[i],NULL};
        if(module(args))return -1;
    }
    char serial[64];snprintf(serial,sizeof(serial),"iSerialNumber=JZ08-INIT-%s",nonce);
    char *args[]={"modprobe","g_ether","idVendor=0x1d6b","idProduct=0x0104",serial,
                  "iManufacturer=INFEND","iProduct=JZ08_OpenWrt",
                  "dev_addr=02:73:00:00:00:01","host_addr=02:73:00:00:00:02",NULL};
    return module(args);
}

static void copy(FILE *out,const char *name) {
    char b[4096];FILE *in=fopen(name,"r");fprintf(out,"[%s]\n",name);
    if(!in){fputs("UNAVAILABLE\n",out);return;}
    while(fgets(b,sizeof(b),in))fputs(b,out);
    fclose(in);
}
int main(int argc,char **argv) {
    if(argc==2 && !strcmp(argv[1],"--reboot-recovery")) {
        sync();return syscall(SYS_reboot,LINUX_REBOOT_MAGIC1,LINUX_REBOOT_MAGIC2,
                              LINUX_REBOOT_CMD_RESTART2,"recovery");
    }
    if(getpid()!=1)return 2;
    mkdir("/proc",0755);mkdir("/sys",0755);mkdir("/dev",0755);
    if(mount("proc","/proc","proc",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL) ||
       mount("sysfs","/sys","sysfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL))return 3;
    char cmd[8192]={0},nonce[33]={0};FILE *f=fopen("/proc/cmdline","r");
    if(f){if(!fgets(cmd,sizeof(cmd),f))cmd[0]=0;fclose(f);}
    char *p=strstr(cmd,"xarkon.nonce=");
    if(p){p+=13;if(strspn(p,"0123456789abcdef")==32)memcpy(nonce,p,32);}
    if(!nonce[0])return 4;
    /* Finite recovery return even if USB service setup fails. */
    pid_t timer=fork();
    if(timer<0)return 9;
    if(timer==0){
        close(0);close(1);close(2);sleep(600);
        syscall(SYS_reboot,LINUX_REBOOT_MAGIC1,LINUX_REBOOT_MAGIC2,
                LINUX_REBOOT_CMD_RESTART2,"recovery");_exit(1);
    }
    f=fopen("/jz08-init-proof.txt","w");if(!f)return 5;
    fprintf(f,"BEGIN %s\nINIT=INFEND_JZ08_FULL_OPENWRT\n",nonce);
    printf("INFEND_JZ08_INIT_REACHED %s\n",nonce);fflush(stdout);
    /* Do not wait for rcS/network to expose the first /init heartbeat. */
    int usb=early_usb(nonce);
    fprintf(f,"EARLY_USB_MODULES=%d\n",usb==0);
    printf("INFEND_JZ08_EARLY_USB_MODULES=%d\n",usb==0);fflush(stdout);
    for(int wait=0;wait<15 && access("/sys/block/mmcblk0/dev",R_OK);wait++)sleep(1);
    int ok=1,count=0;fputs("PERSISTENT_MOUNTS=0\n",f);
    DIR *blocks=opendir("/sys/class/block");struct dirent *entry;
    if(blocks)while((entry=readdir(blocks))) {
        if(strncmp(entry->d_name,"mmcblk",6))continue;
        unsigned int major=0,minor=0;int one=0;char path[512];
        snprintf(path,sizeof(path),"/sys/class/block/%s/dev",entry->d_name);
        FILE *dev=fopen(path,"r");
        if(dev && fscanf(dev,"%u:%u",&major,&minor)==2 && major==179){
            mknod("/dev/jz08-emmc",S_IFBLK|0600,makedev(major,minor));
            int fd=open("/dev/jz08-emmc",O_RDONLY),ro=1;
            if(fd>=0){one=ioctl(fd,BLKROSET,&ro)==0;close(fd);}
            unlink("/dev/jz08-emmc");
        }
        if(dev)fclose(dev);
        fprintf(f,"BLOCK %s force_readonly=%d\n",entry->d_name,one);
        count++;if(!one)ok=0;
    }
    if(blocks)closedir(blocks);
    if(!ok){fputs("EMMC_READONLY_FAILED\n",f);fclose(f);return 8;}
    fprintf(f,"BLOCK_READONLY_COUNT=%d\n",count);
    copy(f,"/sys/block/mmcblk0/size");copy(f,"/proc/meminfo");copy(f,"/proc/partitions");
    fprintf(f,"END %s\n",nonce);fclose(f);
    /* Original OpenWrt /init copies rootfs onto tmpfs before procd jails.
     * Detach only our pseudo mounts before it copies the directory tree. */
    if(umount("/sys") || umount("/proc"))return 6;
    setenv("INITRAMFS","1",1);
    execl("/init.openwrt","/init.openwrt",(char *)NULL);
    return 7;
}
