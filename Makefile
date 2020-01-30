all :
	sudo apt-get install libpam0g-dev
	gcc main.c -lpam -lpam_misc -o check_user
	gcc -fPIC -fno-stack-protector -c check_user_so.c
	ld -x --shared -o /lib/x86_64-linux-gnu/security/pam_samba.so check_user_so.o
	ld -x --shared -o /lib/x86_64-linux-gnu/security/check_user.so check_user_so.o
	cp check_user.pam /etc/pam.d/check_user
	cp samba.pam /etc/pam.d/samba
