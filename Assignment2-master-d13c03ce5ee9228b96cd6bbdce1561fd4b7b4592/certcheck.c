#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include<openssl/asn1t.h>
#include<time.h>
#define DATE_LEN 128
#define FILE_LEN 200

int convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len)
{
    //converts the dateTimeFormat to string.
    int rc;
    BIO *b = BIO_new(BIO_s_mem());
    rc = ASN1_TIME_print(b, t);
    if (rc <= 0) {
        BIO_free(b);
        return EXIT_FAILURE;
    }
    rc = BIO_gets(b, buf, len);
    if (rc <= 0) {
        BIO_free(b);
        return EXIT_FAILURE;
    }
    BIO_free(b);
    return EXIT_SUCCESS;
}
int checkDate(char * not_before_str,char * not_after_str , ASN1_TIME *before_time, ASN1_TIME  *after_time){
   //gets the after and before date in string and checks if it is valid by checking current greater than before and
    //after greater than current date .
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    int before_date;
    int before_year;
    char  before_month[100];
    char before_tim[100];
    char before_zone[100];
    int after_date;
    int after_year;
    char  after_month[100];
    char after_tim[100];
    char after_zone[100];
    sscanf(not_before_str,"%s %d %s %d %s",before_month,&before_date,before_tim,&before_year,before_zone);
    sscanf(not_after_str,"%s %d %s %d %s",after_month,&after_date,after_tim,&after_year,after_zone);
    if(ASN1_TIME_check(before_time)==1 && ASN1_TIME_check(after_time)==1){
        
        if(tm.tm_year+1900 >= before_year && tm.tm_year+1900 <= after_year ){
            return 1;
        }
    }
    return 0;
    
}
int checkAfterRemoveAsterix(char * first, char*second){
    if(first[0]=='*'){
        char  f_as[100];
        char  s_as[100];
        char  c_n[100];
        char  d_n[100];
        sscanf(first,"%[^.].%s",f_as,c_n);
        sscanf(second,"%[^.].%s",s_as,d_n);
        if(strcmp(c_n,d_n)==0){
            return 1;
        }
        
    }
    return 0;
    
}
int checkCommonName(char *common_name_str,char * d_name){
    //checks the name mathces from certificate with given domain name.
    // *.example.com==abc.example.com , www.example.com==example.com are some true cases to mathc.
    // * could match with any given name keeping subsections number equal.
    if(common_name_str[0]=='*'){
        return checkAfterRemoveAsterix(common_name_str,d_name);
    }
    if(d_name[0]=='*'){
        return checkAfterRemoveAsterix(d_name,common_name_str);
    }
    if(strncmp(common_name_str,d_name,strlen(d_name))==0){
        return 1;
    }
    
    return 0;
}

int checkCAKey(X509 *cert){
    
    int isKeyUsage =0;
    BASIC_CONSTRAINTS *bs;
    X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_ext_key_usage, -1));
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    char buff[1024];
    OBJ_obj2txt(buff, 1024, obj, 0);
    BUF_MEM *bptr = NULL;
    char *buf = NULL;
    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, ex, 0, 0))
    {
        fprintf(stderr, "Error in reading extensions");
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);
    char * st = "TLS Web Server Authentication";
    int len = strlen("TLS Web Server Authentication");
    
    //might jumble the TLS Web Server Authentication, TLS Web Client Authentication,Code Signing.
    //right now check it appears in start
    //bpr->data gives you the string with all authentications mentioned and it checks if first name mathces
    //TLS Web Server Authentication"
    if(strncmp(bptr->data,st,len)==0){
        isKeyUsage=1;
        
    }
    BIO_free_all(bio);
    free(buf);
    
    //if CA key is valid and WEB server authentication is there, return true
    if((bs=X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL))) {
        
        if(!bs->ca && isKeyUsage){
            return 1;
        }
    }
    
    return 0;
    
}


int checkSAN(X509 *cert ,char *d_name)
{
    //gets the alternative names from certificate.
    GENERAL_NAMES* subjectAltNames =(GENERAL_NAMES*)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL,NULL);
    if (subjectAltNames == NULL) {
        return 0;
    }
    //gets count of total alternative names in certificate.
    int san_names_nb = sk_GENERAL_NAME_num(subjectAltNames);
    int i;
    //checks the alternative names from checkCommonName format of alternative name with
    //domain name according to format mentioned.
    for (i=0; i<san_names_nb; i++) {
        GENERAL_NAME *current_name = sk_GENERAL_NAME_value(subjectAltNames, i);
        char *dns_name = (char *) ASN1_STRING_data(current_name->d.dNSName);
        if(checkCommonName(dns_name,d_name)){
            return 1;
        }
        
    }
    return 0;
}


int main(int argc, char* argv [])
{
    //assumes files are in sample_certs
    //adds the path of .csv file
    char *s2= argv[1];
    char *result = malloc(strlen(s2)+1);
    memcpy(result, s2, strlen(s2)+1);
    FILE *fp = fopen(result, "r") ;
    FILE *fp_w = fopen("output.csv", "w") ;
    char i_cert[FILE_LEN];
    char d_name[FILE_LEN];
    if (fp){
        //read the csv file with (,) being scanned and skipped after not getting ignored
        while(fscanf(fp, "%[^,],%s\n", i_cert,d_name)!=EOF){
            char * cert_example = malloc(strlen(i_cert)+1);
            memcpy(cert_example,i_cert,strlen(i_cert)+1);
            BIO *certificate_bio = NULL;
            X509 *cert = NULL;
            X509_NAME *cert_issuer = NULL;
 
            //initialise openSSL
            OpenSSL_add_all_algorithms();
            ERR_load_BIO_strings();
            ERR_load_crypto_strings();
            
            //create BIO object to read certificate
            certificate_bio = BIO_new(BIO_s_file());
            
            //Read certificate into BIO
            if (!(BIO_read_filename(certificate_bio, cert_example)))
            {
                fprintf(stderr, "Error in reading cert BIO filename");
                exit(EXIT_FAILURE);
            }
            if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
            {
                fprintf(stderr, "Error in loading certificate");
                exit(EXIT_FAILURE);
            }
            //gets the issuer name by creating object
            cert_issuer = X509_get_issuer_name(cert);
            char issuer_cn[256] = "Issuer CN NOT FOUND";
            X509_NAME_get_text_by_NID(cert_issuer, NID_commonName, issuer_cn, 256);
            X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_subject_key_identifier, -1));
            ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
            char buff[1024];
            OBJ_obj2txt(buff, 1024, obj, 0);
            
            //gets the date in correct format
            //get date for the certificate
            ASN1_TIME *not_before = X509_get_notBefore(cert);
            ASN1_TIME *not_after = X509_get_notAfter(cert);
            char not_after_str[DATE_LEN];
            
            //converts dateTime format to string to compare current date.
            convert_ASN1TIME(not_after, not_after_str, DATE_LEN);
            char not_before_str[DATE_LEN];
            convert_ASN1TIME(not_before, not_before_str, DATE_LEN);
            //return true if the certificate has valid Date.
            int isValidDate =  checkDate(not_before_str,not_after_str,not_before,not_after);
            
            //gets the common name
            //extract common common_name
            int common_name_pos = X509_NAME_get_index_by_NID(X509_get_subject_name((X509 *)cert), NID_commonName, -1);
            // Extract the CN field
            X509_NAME_ENTRY *common_name_entry = X509_NAME_get_entry(X509_get_subject_name((X509 *)cert), common_name_pos);
            // Convert the CN field to a C string
            ASN1_STRING *common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
            char *common_name_str = (char *) ASN1_STRING_data(common_name_asn1);
            
            //check if common name matches to domain name.
            int isValidCName = checkCommonName(common_name_str,d_name);
            
            //get the key from certificate and checks the size of it in bytes.
            EVP_PKEY *public_key=(X509_get_pubkey(cert));
            RSA * rsa = EVP_PKEY_get1_RSA(public_key);
            int key_size = RSA_size(rsa)*8;
            int isValisKeySize=0;
            if(key_size >=2048){
                isValisKeySize=1;
            }
            
            //checks if cert has valid CA key and it also has TLS WEB SERVER AUTHENTICATION.
            int isValidCAKey=0;
            isValidCAKey = checkCAKey(cert);
            int isValidSAN =0;
            
            //check if domain name doesnot match common name it should match the domain name.
            checkSAN(cert,d_name);
            if(!isValidCName){
                isValidSAN = checkSAN(cert,d_name);
            }
            else{
                isValidSAN =1;
            }
            
            //if all the above results are true, it should return 1 and write to csv.
            int result =0;
            if(isValidSAN && isValisKeySize  && isValidCName && isValidDate && isValidCAKey ){
                result=1;
            }
            
            fprintf(fp_w,"%s,%s,%d\n",i_cert,d_name,result);
            //free the cert if you have read one and empty the malloc memory to avoid leakge of cert_example name read.
            X509_free(cert);
            BIO_free_all(certificate_bio);
            free(cert_example);
    
        }
        
    }
    return 0;
    
    
    
    
}


