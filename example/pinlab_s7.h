#include<stdio.h>
#include<stdlib.h>
#include "uthash.h"
 

typedef struct onebyte_data{
    char s[50];
    uint8_t flag;
}odata;

static odata funk0[8];
static odata funk1[8];
static odata funk2[8];
static odata trgereig0[8];
static odata trgereig1[8];

uint16_t sum_byte(uint8_t x,uint8_t y){
    uint16_t data=0;

    data=x;
    data=(data<<8)+y;

    return data;
}

void init_flag(){
  strcpy(funk0[0].s,"Reserverd");
  strcpy(funk0[1].s,"BLock status");
  strcpy(funk0[2].s,"Variable status");
  strcpy(funk0[3].s,"Output ISTACK");
  strcpy(funk0[4].s,"Output BSTACK");
  strcpy(funk0[5].s,"Output LSTACK");
  strcpy(funk0[6].s,"Time measurement from");
  strcpy(funk0[7].s,"Force selection");

  strcpy(funk1[0].s,"Modify variable");
  strcpy(funk1[1].s,"Force");
  strcpy(funk1[2].s,"Breakpoint");
  strcpy(funk1[3].s,"Exit HOLD");
  strcpy(funk1[4].s,"Memory reset");
  strcpy(funk1[5].s,"Disable job");
  strcpy(funk1[6].s,"Enable job");
  strcpy(funk1[7].s,"Delete job");

  strcpy(funk2[0].s,"Read job list");
  strcpy(funk2[1].s,"Read job");
  strcpy(funk2[2].s,"Replace job");
  strcpy(funk2[3].s,"Reserved");
  strcpy(funk2[4].s,"Reserved");
  strcpy(funk2[5].s,"Reserved");
  strcpy(funk2[6].s,"Reserved");
  strcpy(funk2[7].s,"Reserved");

  strcpy(trgereig0[0].s,"Immediately");
  strcpy(trgereig0[1].s,"System trigerr");
  strcpy(trgereig0[2].s,"System checkpoint main cycle start");
  strcpy(trgereig0[3].s,"System checkpoint main cycle end");
  strcpy(trgereig0[4].s,"Mode transition RUN-STOP");
  strcpy(trgereig0[5].s,"After code address");
  strcpy(trgereig0[6].s,"Code address area");
  strcpy(trgereig0[7].s,"Data address");

  strcpy(trgereig1[0].s,"Data address area");
  strcpy(trgereig1[1].s,"Local data address");
  strcpy(trgereig1[2].s,"Local data address area");
  strcpy(trgereig1[3].s,"Range trigger");
  strcpy(trgereig1[4].s,"Before code address");
  strcpy(trgereig1[5].s,"Reserved");
  strcpy(trgereig1[6].s,"Reserved");
  strcpy(trgereig1[7].s,"Reserved");

  for(int i=0;i<8;i++){
    funk0[i].flag=0;
    funk1[i].flag=0;
    funk2[i].flag=0;
    trgereig0[i].flag=0;
    trgereig1[i].flag=0;
  }
}

void print_onebyte_flag(uint8_t flags, odata* func,FILE *fp){

    for(int i=0;i<8;i++){
        if(((flags>>i)&0x01)==0x01)
            func[i].flag=1;
        else
            func[i].flag=0;
    }

    for(int i=0;i<8;i++){
        fprintf(fp, "  %s : ",func[i].s);
        if(func[i].flag==1)
            fprintf(fp, "True\n");
        else
            fprintf(fp, "False\n");  
    }

    fprintf(fp, "\n");
}

void bit_analysis(uint8_t *s7packet,unsigned long packet_len,uint16_t id, uint16_t index,FILE *fp){

    init_flag();
    uint32_t s7key=0;
    int16_t seq,data,no=1;
    uint8_t flags=0;
    uint8_t *packet_checked=(uint8_t*)malloc(packet_len);
    memcpy(packet_checked,s7packet,packet_len);

        //exception handling
    if(packet_checked[0]!=0xff){
        fprintf(fp, "Error // Return code : 0x%.2x\n",packet_checked[0]);
    }

    s7key=id;
    s7key=(s7key<<16)+index;

    switch(s7key){
        case 0x00000000:
            for(seq = 12; seq<packet_len; seq+=2){
                data = packet_checked[12+(no-1)*2];
                data = (data<<8)+packet_checked[12+(no-1)*2+1];
                fprintf(fp, "SZL data tree (list count no. %d) SZL ID that exists : 0x%.4x\n", no, data);
                no++;
            }
            break;
        case 0x00110000:
            for(seq = 12; seq<packet_len; seq+=28){
                fprintf(fp, "SZL data tree (list count no. %d)\n", no);
                data = packet_checked[seq];
                data = (data<<8)+packet_checked[seq+1];
                fprintf(fp, "Index : 0x%.4x\n", data);
                fprintf(fp, "MlfB (Order number of the module) : ");
                for(int i = 0; i<20; i++) fprintf(fp, "%c", packet_checked[seq+2+i]);
                fprintf(fp, "\n");
                data = packet_checked[seq+22];
                data = (data<<8)+packet_checked[seq+23];
                fprintf(fp, "BGTyp (Module type ID) : 0x%.4x\n", data);
                data = packet_checked[seq+24];
                data = (data<<8)+packet_checked[seq+25];
                fprintf(fp, "Ausbg (Version of the module or release of the operating system) : 0x%.4x\n", data);
                data = packet_checked[seq+26];
                data = (data<<8)+packet_checked[seq+27];
                fprintf(fp, "Ausbe (Release of the PG description) : 0x%.4x\n\n", data);
                no++;
            }
            break;
        case 0x001a0000:
            for(seq = 12; seq<packet_len; seq+=12){
                fprintf(fp, "SZL data tree (list count no. %d) ", no);
                fprintf(fp, "SZL partial list data : 0x");
                for(int i = 0; i<12; i++){
                    fprintf(fp, "%.2x", packet_checked[seq+i]);
                }
                fprintf(fp, "\n");
                no++;
            }
            break;
        case 0x001b0000:
            for(seq = 12; seq<packet_len; seq+=20){
                fprintf(fp, "SZL data tree (list count no. %d) ", no);
                fprintf(fp, "SZL partial list data : 0x");
                for(int i = 0; i<20; i++){
                    fprintf(fp, "%.2x", packet_checked[seq+i]);
                }
                fprintf(fp, "\n");
                no++;
            }
            break;
        case 0x001c0000:
            for(seq = 12; seq<packet_len-34; seq+=34){
                fprintf(fp, "SZL data tree (list count no. %d) ", no);
                fprintf(fp, "SZL partial list data : 0x");
                for(int i = 0; i<34; i++){
                    fprintf(fp, "%.2x", packet_checked[seq+i]);
                }
                fprintf(fp, "\n");
                no++;
            }
            data = packet_checked[seq];
            data = (data<<8)+packet_checked[seq+1];
            fprintf(fp, "SZL data tree [Fragment, complete response doesn't fit one PDU] ");
            fprintf(fp, "SZL data : 0x%.4x\n", data);
            break;
        case 0x003a0000:
            fprintf(fp, "No data tree.\n");
            break;
        case 0x00740000:
            for(seq = 12; seq<packet_len; seq+=4){
                fprintf(fp, "SZL data tree (list count no. %d)\n", no);
                data = packet_checked[seq];
                data = (data<<8)+packet_checked[seq+1];
                fprintf(fp, "cpu_led_id : 0x%.4x\n", data);
                data = (packet_checked[seq]&0x07);
                fprintf(fp, "Bits 0, 1, 2 : Rack number : 0x%.2x\n", data);
                data = (packet_checked[seq]&0x08);
                fprintf(fp, "Bits 3 : CPU Type (0=Standby, 1=Master) : 0x%.2x\n", data/8);
                fprintf(fp, "Byte 1 : LED ID : 0x%.2x\n", packet_checked[seq+1]);
                fprintf(fp, "Status of the LED : %s\n", packet_checked[seq+2]==0?"Off":"On");
                fprintf(fp, "Flashing status of the LED : %s\n\n", packet_checked[seq+3]==0?"Not flashing":"Flashing");
                no++;
            }
            break;
        case 0x00a00000:
            for(seq = 12; seq<packet_len; seq+=20){
                fprintf(fp, "SZL data tree (list count no. %d)\n", no);
                fprintf(fp, "Event ID : 0x");
                for(int i = 0; i<2; i++){
                    fprintf(fp, "%.2x", packet_checked[seq+i]);
                }
                fprintf(fp, "\nEvent class : 0x%.2x\n", (packet_checked[seq]&0xF0)/16);
                fprintf(fp, "Event entering : 0x%.2x\n", (packet_checked[seq]&0x01));
                fprintf(fp, "Entry in diagnostic buffer : %s\n", (packet_checked[seq]&0x02)==0?"False":"True");
                fprintf(fp, "Internal error : %s\n", (packet_checked[seq]&0x04)==0?"False":"True");
                fprintf(fp, "External errer : %s\n", (packet_checked[seq]&0x08)==0?"False":"True");
                fprintf(fp, "Event number : 0x%.2x\n", packet_checked[seq+1]);
                fprintf(fp, "Prioriry class : 0x%.2x\n", packet_checked[seq+2]);
                fprintf(fp, "OB number : 0x%.2x\n", packet_checked[seq+3]);
                fprintf(fp, "DatID : 0x");
                for(int i = 4; i<6; i++){
                    fprintf(fp, "%.2x", packet_checked[seq+i]);
                }
                fprintf(fp, "\nINF01 Additional information 1 : 0x");
                for(int i = 6; i<8; i++){
                    fprintf(fp, "%.2x", packet_checked[seq+i]);
                }
                fprintf(fp, "\nINF01 Additional information 2 : 0x");
                for(int i = 8; i<12; i++){
                    fprintf(fp, "%.2x", packet_checked[seq+i]);
                }
                fprintf(fp, "\nS7 Timestamp - Year : 0x%.2x", packet_checked[seq+12]);
                fprintf(fp, "\nS7 Timestamp - Month : 0x%.2x", packet_checked[seq+13]);
                fprintf(fp, "\nS7 Timestamp - Day : 0x%.2x", packet_checked[seq+14]);
                fprintf(fp, "\nS7 Timestamp - Hour : 0x%.2x", packet_checked[seq+15]);
                fprintf(fp, "\nS7 Timestamp - Minute : 0x%.2x", packet_checked[seq+16]);
                fprintf(fp, "\nS7 Timestamp - Second : 0x%.2x", packet_checked[seq+17]);
                fprintf(fp, "\nS7 Timestamp - Milliseconds : 0x%.2x%x", packet_checked[seq+18], (packet_checked[seq+19]/16));
                fprintf(fp, "\nS7 Tinestamp - Weekday : 0x%.2x\n\n", (packet_checked[seq+19]&0x0F));
                no++;
            }
            break;
        case 0x01110001:
            seq = 12;
            data = packet_checked[seq];
            data = (data<<8)+packet_checked[seq+1];
            fprintf(fp, "Index : 0x%.4x\n", data);
            fprintf(fp, "MlfB (Order number of the module) : ");
            for(int i = 0; i<20; i++) fprintf(fp, "%c", packet_checked[seq+2+i]);
            fprintf(fp, "\n");
            data = packet_checked[seq+22];
            data = (data<<8)+packet_checked[seq+23];
            fprintf(fp, "BGTyp (Module type ID) : 0x%.4x\n", data);
            data = packet_checked[seq+24];
            data = (data<<8)+packet_checked[seq+25];
            fprintf(fp, "Ausbg (Version of the module or release of the operating system) : 0x%.4x\n", data);
            data = packet_checked[seq+26];
            data = (data<<8)+packet_checked[seq+27];
            fprintf(fp, "Ausbe (Release of the PG description file) : 0x%.4x\n\n", data);
            break;
        case 0x01120100:
            for(seq = 12; seq<packet_len; seq+=2){
            fprintf(fp, "SZL data tree (list count no. %d) ", no);
            fprintf(fp, "SZL partial list data : 0x");
            for(int i = 0; i<2; i++){
            fprintf(fp, "%.2x", packet_checked[seq+i]);
            }
            fprintf(fp, "\n");
            no++;
            }
            break;
        case 0x01120200:
            fprintf(fp, "No data tree.\n");
            break;
        case 0x01310001:
            for(seq = 12; seq<packet_len; seq+=40){
                fprintf(fp, "SZL data tree (list count no. %d) ", no);
                data = packet_checked[seq];
                data = (data<<8)+packet_checked[seq+1];
                fprintf(fp, "Index : 0x%.4x\n", data);
                data = packet_checked[seq+2];
                data = (data<<8)+packet_checked[seq+3];
                fprintf(fp, "pdu (Maximum PDU size in bytes) : 0x%.4x\n", data);
                data = packet_checked[seq+4];
                data = (data<<8)+packet_checked[seq+5];
                fprintf(fp, "anz (Maximum number of communication connections) : 0x%.4x\n", data);
                fprintf(fp, "mpi_bps (Maximum data rate of the MPI in hexadecimal format) : 0x");
                for(int i = 6; i<10; i++){
                    fprintf(fp, "%.2x", packet_checked[seq+i]);
                }
                fprintf(fp, "\nmkbus_bps (Maximum data rate of the communicaton bus) : 0x");
                for(int i = 10; i<14; i++){
                    fprintf(fp, "%.2x", packet_checked[seq+i]);
                }
                fprintf(fp, "\nres (Reserved) : 0x");
                for(int i = 14; i<40; i++){
                    fprintf(fp, "%.2x", packet_checked[seq+i]);
                }
                fprintf(fp, "\n");
                no++;
            }
            break;
        case 0x01310002:
            print_onebyte_flag(packet_checked[14],funk0,fp);
            print_onebyte_flag(packet_checked[15],funk1,fp);
            print_onebyte_flag(packet_checked[16],funk2,fp);
            print_onebyte_flag(packet_checked[16],funk2,fp);
            print_onebyte_flag(packet_checked[20],trgereig0,fp);
            print_onebyte_flag(packet_checked[21],trgereig1,fp);
            break;
        case 0x01310004:
            //flag
            break;
        case 0x01310005:
            fprintf(fp, "SZL data tree (list count no. %d)\n",no);
            fprintf(fp, "SZL partial list data : 0x");
            for(seq=12;seq<packet_len;seq++)
                fprintf(fp, "%.2x",packet_checked[seq]);
            fprintf(fp, "\n");
            break;
        case 0x01310006:
            //flag
            break;
        case 0x01310009:
            fprintf(fp, "SZL data tree (list count no. %d)\n",no);
            fprintf(fp, "SZL partial list data : 0x");
            for(seq=12;seq<packet_len;seq++)
                fprintf(fp, "%.2x",packet_checked[seq]);
            fprintf(fp, "\n");
            break;
        case 0x01320001:
            fprintf(fp, "SZL data tree (list count no. %d)\n",no);
            fprintf(fp, "res pg : 0x%.4x\n",sum_byte(packet_checked[14],packet_checked[15]));
            fprintf(fp, "res os : 0x%.4x\n",sum_byte(packet_checked[16],packet_checked[17]));
            fprintf(fp, "u pg : 0x%.4x\n",sum_byte(packet_checked[18],packet_checked[19]));
            fprintf(fp, "u od : 0x%.4x\n",sum_byte(packet_checked[20],packet_checked[21]));
            fprintf(fp, "proj : 0x%.4x\n",sum_byte(packet_checked[22],packet_checked[23]));
            fprintf(fp, "auf : 0x%.4x\n",sum_byte(packet_checked[24],packet_checked[25]));
            fprintf(fp, "free : 0x%.4x\n",sum_byte(packet_checked[26],packet_checked[27]));
            fprintf(fp, "used : 0x%.4x\n",sum_byte(packet_checked[28],packet_checked[29]));
            fprintf(fp, "last : 0x%.4x\n",sum_byte(packet_checked[30],packet_checked[31]));
            fprintf(fp, "res : 0x");
            for(seq=32;seq<packet_len;seq++)
                fprintf(fp, "%.2x",packet_checked[seq]);
            fprintf(fp, "\n");
            break;
        case 0x01320004:
            fprintf(fp, "SZL data tree (list count no. %d)\n",no);
            fprintf(fp, "key : 0x%.2x\n",sum_byte(packet_checked[14],packet_checked[15]));
            fprintf(fp, "param : 0x%.2x\n",sum_byte(packet_checked[16],packet_checked[17]));
            fprintf(fp, "real : 0x%.2x\n",sum_byte(packet_checked[18],packet_checked[19]));
            fprintf(fp, "bart_sch : 0x%.2x\n",sum_byte(packet_checked[20],packet_checked[21]));
            fprintf(fp, "crst_wrst : 0x%.2x\n",sum_byte(packet_checked[22],packet_checked[23]));
            fprintf(fp, "res : 0x");
            for(seq=24;seq<packet_len;seq++)
                fprintf(fp, "%.2x",packet_checked[seq]);
            fprintf(fp, "\n");
            break;
        case 0x01320008:
        case 0x01320009:
        case 0x0132000b:
            fprintf(fp, "SZL data tree (list count no. %d)\tSZL ID that exits : 0x",no);
            for(seq=12;seq<packet_len;seq++)
                fprintf(fp, "%.2x",packet_checked[seq]);
            fprintf(fp, "\n");
            break;
        case 0x01740006:
            fprintf(fp, "SZL data tree (list count no. %d)\tSZL ID that exits : ",no);
            fprintf(fp, "Rack number : 0x%.2x\n",packet_checked[12]&0b00000111);
            fprintf(fp, "CPU Type (0=Standby, 1=Master) : 0x%.2x\n",(packet_checked[12]&0b00001000)>>3);
            fprintf(fp, "LED ID : 0x%.2x\n",packet_checked[13]);
            fprintf(fp, "Status of the LED : %s\n",packet_checked[14]==0?"OFF":"ON");
            fprintf(fp, "Flashing status of the  LED : %s\n",packet_checked[15]==0?"Not flashing":"flashing");
            break;
        case 0x02220001:
        case 0x02220050:
            fprintf(fp, "SZL data tree (list count no. %d)\tSZL ID that exits : 0x",no);
            for(seq=12;seq<packet_len;seq++)
                fprintf(fp, "%.2x",packet_checked[seq]);
            fprintf(fp, "\n");
            break;
        case 0x04240000:
            fprintf(fp, "SZL data tree (list count no. %d)\n",no);
            data=(packet_checked[12]<<8)|packet_checked[13];
            fprintf(fp, "ereig : 0x%.4x\n",data);
            fprintf(fp, "ae : 0x%.2x\n",packet_checked[14]);
            fprintf(fp, "buz-id : 0x%.2x\n",packet_checked[15]);
            fprintf(fp, "anlinfo1 : 0x%.2x\n",packet_checked[20]);
            fprintf(fp, "anlinfo2 : 0x%.2x\n",packet_checked[21]);
            fprintf(fp, "anlinfo3 : 0x%.2x\n",packet_checked[22]);
            fprintf(fp, "anlinfo4 : 0x%.2x\n",packet_checked[23]);
            fprintf(fp, "time : 0x");
            for(seq=24;seq<packet_len;seq++)
                fprintf(fp, "%.2x",packet_checked[seq]);
            fprintf(fp, "\n");
            break;
        case 0x0d910000:
            fprintf(fp, "SZL data tree (list count no. %d)\tSZL ID that exits : 0x",no);
            for(seq=12;seq<packet_len;seq++)
                fprintf(fp, "%.2x",packet_checked[seq]);
            fprintf(fp, "\n");
            break;
        case 0x0f110000:
        case 0x0f120000:
        case 0x0f1a0000:
        case 0x0f1b0000:
        case 0x0f1c0000:
        case 0x0f3a0000:
        case 0x0f740000:
            fprintf(fp, "No data tree.\n");
            break;
        default:
            fprintf(fp, "Undefined s7 ID/Index\n");
            break;
    }

    fprintf(fp, "\n");
    free(packet_checked);
}