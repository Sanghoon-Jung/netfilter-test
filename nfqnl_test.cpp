#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <string>
#include <libnet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT, NF_DROP */
#include <libnetfilter_queue/libnetfilter_queue.h>
#define HTTP_DPORT 80

void err(const char* errmsg, int errnum);
bool isHarmSite(unsigned char* buf, int size);
static u_int32_t print_pkt (struct nfq_data *tb);
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data);

/* ip, tcp 정보를 확인하기 위한 구조체 */
#pragma pack(push, 1)
struct IPTCP{
	struct libnet_ipv4_hdr ip_hdr;
	struct libnet_tcp_hdr tcp_hdr;
};
#pragma pack(pop)

/* 유해사이트 차단을 위한 전역변수 */
bool isharm = false;
char* harm_site;
char host_data[BUFSIZ];

/* main 함수 */
int main(int argc, char **argv){
	
	if(argc != 2){
		printf("syntax : %s <host to block>\n", argv[0]);
		printf("sample : %s test.gilgil.net\n", argv[0]);
		exit(-1);
	}

	harm_site = argv[1];
	sprintf(host_data, "Host: %s\r\n", harm_site);	

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) err("error during nfq_open()\n", 1);

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) err("error during nfq_unbind_pf()\n", 1);

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) err("error during nfq_bind_pf()\n", 1);

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) err("error during nfq_create_queue()\n", 1);

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) err("can't set packet_copy mode\n", 1);
	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

void err(const char* errmsg, int errnum){
	fprintf(stderr, errmsg);
	exit(errnum);
}

// 유해 사이트로의 접근인지 확인
bool isHarmSite(unsigned char* buf, int size){
	struct IPTCP* header = reinterpret_cast<IPTCP*>(buf);
	
	/* 1st. ipv4인지, tcp protocol인지, http인지 확인  */
	if(header->ip_hdr.ip_v == 4 && header->ip_hdr.ip_p == IPPROTO_TCP
	   && ntohs(header->tcp_hdr.th_dport) == HTTP_DPORT){
		
		/* 2nd. http data의 Host 가 test.gilgil.net인지 확인 */
		int datapos = (header->ip_hdr.ip_hl + header->tcp_hdr.th_off) * 4;
		std::string httpdata(reinterpret_cast<char*>(buf+datapos));
		
		if(httpdata.find(host_data) != -1) return true;		// host_data 에는 "Host: <사이트명>\r\n" 이 들어있음.
	}

	return false;	// 위의 필터를 모두 통과시 유해사이트가 아님
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb){
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	// nfq_get_payload : data 변수가 IP packet의 시작 위치를 가리킨다.
	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		printf("payload_len=%d ", ret);
		isharm = isHarmSite(data, ret);
	}

	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data){
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	/* nfq_set_verdict 함수의 3번째 인자를
	 * NF_ACCEPT나 NF_DROP 가ㅄ으로 호출함으로써
	 * 패킷을 accept하거나 drop시킬 수 있음
	 */
	
	if(isharm){
		printf("!!!!!! WARNING !!!!!! You are trying to acces blocked site.\n");
		printf("You can't access to %s\n\n", harm_site);
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}