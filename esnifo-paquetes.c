//---------------------
/* esnifo-paquetes.c*/
//--------------------
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<arpa/inet.h> 
#include<string.h>
#include<unistd.h>
#define ROJO "\x1b[31m"
#define AMARILLO  "\x1b[33m"
#define CYAN    "\x1b[36m"
#define VERDE        "\x1b[32m"
/*Llamada a mensajes*/
void los_mensajes(char *mensaje)
 {
   char error_mensaje[100];
   strcpy(error_mensaje, "Se ha cometido un error: ");
   strncat(error_mensaje, mensaje, 83);
   perror(error_mensaje);
   exit(-1);
}

/* Error chequeado por la función  malloc(), en la 
asignación dinámica de memoria, definidas en stdlib.h
*/

void *ec_malloc(unsigned int size) {
   void *ptr;
   ptr = malloc(size);
   if(ptr == NULL)
      los_mensajes("utilizamos ec_malloc() para la asignación de memoria");
   return ptr;
}


int main(void)
{

char *tarjeta_red;
int  salida;    /* Salida del comando */
char comando[60];

    char ip[13]; /*Reserva espacio ip*/
    char subnet_mask[13];/* Reservamos espacio en memoria para mascara de red*/
    bpf_u_int32 ip_raw;  /* Nuestra IP */
    bpf_u_int32 subnet_mask_raw; /* La máscara de red de nuestro dispositivo rastreador */
    int lookup_return_code;/*número codigo de error*/
    char error_buffer[PCAP_ERRBUF_SIZE];
    /* definido en pcap.h
    cadena de errores */
    struct in_addr address; /* Estructura usada por cada ip y subnet */

    /* Buscamos la tarjeta de red */
    tarjeta_red = pcap_lookupdev(error_buffer);
    if (tarjeta_red == NULL) {
        printf("%s\n", error_buffer);
        return 1;
    }
 printf(CYAN"***********CARACTERISTICAS DE LA RED**********\n" );
 sprintf (comando, "ifconfig");
 salida = system (comando);


    /* Obtener información del dispositivo */
    lookup_return_code = pcap_lookupnet(
        tarjeta_red,
        &ip_raw,
        &subnet_mask_raw,
        error_buffer
    );//Detectamos errores
    if (lookup_return_code == -1) {
        printf("%s\n", error_buffer);
        return 1;
    }

    address.s_addr = ip_raw;
    strcpy(ip, inet_ntoa(address));
    if (ip == NULL) {
        perror("inet_ntoa"); /* Imprimimos si hubiera algún error */
        return 1;
    }
    
    /* Ahora vamos a optener la máscara de subred en formato
     legible  */
    address.s_addr = subnet_mask_raw;
    strcpy(subnet_mask, inet_ntoa(address));
    if (subnet_mask == NULL) {
        perror("inet_ntoa");
        return 1;
    }
//Imprimimos la tarjeta de red, la ip, y la máscara de red
    printf("Tarjeta de red: %s\n", tarjeta_red);
    {

    printf("**************************************************\n");
    printf(ROJO"----------------------------------------------.\n**");
    printf("****¡EN 8 SG. SE VA A INICIAR EL ESNIFADO DE RED!.****\n");
    printf("**************************************************\n");
    printf(VERDE" " );
    sleep(8); //Pausa de 10 segundos
/*
Declaramos constante i de contador, la reserva 
de buffer de 10000 bytes
para almacenar los paquetes, y el descriptor para BSD */

int i, recv_length, descriptor;
u_char buffer[10000];/*dimensión de buffersuficiente
para que no se produzca "stack smashing detected"*/
if ((descriptor = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
los_mensajes("EJECUTAR COMO ROOT");
for(i=0; i < 80; i++) { /*En principio establezco la salida para 20 paquetes.
    para salir de consola pulsar control C*/
recv_length = recv(descriptor, buffer, 8000, 0);
printf("\n**********************************************************************");
printf("\n*Esnifer Tarjeta-red: %s -> Paquete N°:%i de: %d Bytes*",tarjeta_red,i, recv_length);
printf("\n**********************************************************************\n");
/*
Este trozo de código a continuación,
vuelca la memoria sin procesar en bytes hexadecimales
y formato dividido imprimible.
En ella se programan, entre otros, los criterios de 
impresión para que puedan ser legible,
de los volcados esnifados a la red.
unsigned char buffer:almacenar datos binarios arbitrarios
unsigned int length:Indicamos longitud

*/
unsigned char byte;
unsigned int i;

char Codigo_ascii[17];
Codigo_ascii[16] = '\0';
   
for (i = 0; i < recv_length; ++i) {
    byte = buffer[i];
        printf("%02X ", ((unsigned char*)buffer)[i]);
        if (((unsigned char*)buffer)[i] >= ' ' && ((unsigned char*)buffer)[i] <= '~')
         {
            Codigo_ascii[i % 16] = ((unsigned char*)buffer)[i];
        } else {
            Codigo_ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1==recv_length) {
            printf(" ");
            if ((i+1) % 16 == 0) {

                printf(" |  %s \n", Codigo_ascii);
                
            }
            }
            }

            printf("\n" );
}
}
//printf(CYAN"***********CARACTERISTICAS DE LA RED**********\n" );
//sprintf (comando, "ifconfig");
//salida = system (comando);
}

