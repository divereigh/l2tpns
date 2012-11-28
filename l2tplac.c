/*
 * Add functionality "LAC" to l2tpns.
 * Used to forward a ppp session to another "LNS".
 */
#include <errno.h>
#include <string.h>

#include "md5.h"
#include "l2tpns.h"
#include "util.h"

#include "l2tplac.h"

/* sequence diagram: Client <--> LAC <--> LNS1 <--> LNS2
 * 
 *           LCP Negotiation
 * Client <-------------------> LAC
 *         Challenge (CHAP/PAP)
 * Client <-------------------> LAC
 *                                         SCCRQ
 *                              LAC --------------------> LNS1 (Tunnel Open)
 *                                         SCCRP
 *                              LAC <-------------------- LNS1 (Tunnel Open)
 *                                         SCCCN
 *                              LAC --------------------> LNS1 (Tunnel Open)
 *                                         ZLB
 *                              LAC <-------------------- LNS1 (Tunnel Open)
 *                                         ICRQ
 *                              LAC --------------------> LNS1 (Session Open)
 *                                         ICRP
 *                              LAC <-------------------- LNS1 (Session Open)
 *                                         ICCN
 *                              LAC --------------------> LNS1 (Session Open)
 *                                         ZLB
 *                              LAC <-------------------- LNS1 (Session Open)
 *                        LCP Negotiation
 * Client <---------------------------------------------> LNS1
 *                        Challenge (CHAP/PAP)
 * Client <---------------------------------------------> LNS1
 *                                                                    SCCRQ
 *                                                        LNS1 --------------------> LNS2 (Tunnel Open)
 *                                                                    SCCRP
 *                                                        LNS1 <-------------------- LNS2 (Tunnel Open)
 *                                                                    SCCCN
 *                                                        LNS1 --------------------> LNS2 (Tunnel Open)
 *                                                                    ZLB
 *                                                        LNS1 <-------------------- LNS2 (Tunnel Open)
 *                                                                    ICRQ
 *                                                        LNS1 --------------------> LNS2 (Session Open)
 *                                                                    ICRP
 *                                                        LNS1 <-------------------- LNS2 (Session Open)
 *                                                                    ICCN
 *                                                        LNS1 --------------------> LNS2 (Session Open)
 *                                                                    ZLB
 *                                                        LNS1 <-------------------- LNS2 (Session Open)
 *                                   LCP Negotiation
 * Client <------------------------------------------------------------------------> LNS2
 *                                   PAP/CHAP Authentification
 * Client <------------------------------------------------------------------------> LNS2
 *                                   DATA (ppp)
 * Client <------------------------------------------------------------------------> LNS2
 * */

// Limits
#define MAXRLNSTUNNEL	101

typedef uint16_t confrlnsidt;

/*
 * Possible configrlns states
 * TUNNELFREE -> TUNNELOPEN -> TUNNELDIE -> TUNNELFREE
 */
enum
{
	CONFRLNSFREE = 0,	// Not in use
	CONFRLNSSET		// Config Set
};

// struct remote lns
typedef struct
{
	tunnelidt tid;		// near end tunnel ID
	int state;			// conf state (tunnelstate enum)
	in_addr_t ip;		// Ip for far end
	uint16_t port;		// port for far end
	hasht auth;			// request authenticator
	char strmaskuser[MAXUSER];
	char l2tp_secret[64];		// L2TP shared secret
}
configrlns;

configrlns *pconfigrlns = NULL;			// Array of tunnel structures.

// Init data structures
void initremotelnsdata()
{
	confrlnsidt i;

	if ( !(pconfigrlns = shared_malloc(sizeof(pconfigrlns[0]) * MAXRLNSTUNNEL)) )
	{
		LOG(0, 0, 0, "Error doing malloc for tunnels lac: %s\n", strerror(errno));
		exit(1);
	}

	memset(pconfigrlns, 0, sizeof(pconfigrlns[0]) * MAXRLNSTUNNEL);

	// Mark all the tunnels as undefined (waiting to be filled in by a download).
	for (i = 1; i < MAXRLNSTUNNEL; i++)
		pconfigrlns[i].state = CONFRLNSFREE;	// mark it as not filled in.

	config->highest_rlnsid = 0;
}

// Check if must be forwarded to another LNS
int forwardtolns(sessionidt s, char * puser)
{
	tunnelidt t;
	confrlnsidt i;

	for (i = 1; i <= config->highest_rlnsid ; ++i)
	{
		if ( NULL != strstr(puser, pconfigrlns[i].strmaskuser))
		{
			t = pconfigrlns[i].tid;

			if ((t != 0) && (tunnel[t].ip != pconfigrlns[i].ip))
			{
				pconfigrlns[i].tid = t = 0;
				LOG(1, 0, t, "Tunnel ID inconsistency\n");
			}

			if (t == 0)
			{
				if (main_quit == QUIT_SHUTDOWN) return 0;

				// Start Open Tunnel
				if (!(t = lac_new_tunnel()))
				{
					LOG(1, 0, 0, "No more tunnels\n");
					STAT(tunnel_overflow);
					return 0;
				}
				lac_tunnelclear(t);
				tunnel[t].ip = pconfigrlns[i].ip;
				tunnel[t].port = pconfigrlns[i].port;
				tunnel[t].window = 4; // default window
				STAT(tunnel_created);
				LOG(1, 0, t, "New (REMOTE LNS) tunnel to %s:%u ID %u\n", fmtaddr(htonl(tunnel[t].ip), 0), tunnel[t].port, t);

				random_data(pconfigrlns[i].auth, sizeof(pconfigrlns[i].auth));

				pconfigrlns[i].tid = t;

				lac_send_SCCRQ(t, pconfigrlns[i].auth, sizeof(pconfigrlns[i].auth));
			}
			else if (tunnel[t].state == TUNNELOPEN)
			{
				if (main_quit != QUIT_SHUTDOWN)
				{
					/**********************/
					/** Open New session **/
					/**********************/
					sessionidt new_sess = sessionfree;

					sessionfree = session[new_sess].next;
					memset(&session[new_sess], 0, sizeof(session[new_sess]));

					if (new_sess > config->cluster_highest_sessionid)
						config->cluster_highest_sessionid = new_sess;

					session[new_sess].opened = time_now;
					session[new_sess].tunnel = t;
					session[new_sess].last_packet = session[s].last_data = time_now;

					session[new_sess].ppp.phase = Establish;
					session[new_sess].ppp.lcp = Starting;

					// Sent ICRQ  Incoming-call-request
					lac_send_ICRQ(t, new_sess);

					// Set session to forward to another LNS
					session[s].forwardtosession = new_sess;
					session[new_sess].forwardtosession = s;

					STAT(session_created);
				}
				else
				{
					lac_tunnelshutdown(t, "Shutting down", 6, 0, 0);
					pconfigrlns[i].tid = 0;
				}
			}
			else
			{
				/** TODO **/
				LOG(1, 0, t, "(REMOTE LNS) tunnel is not open\n");
			}

			return 1;
		}
	}

	return 0;
}

static tunnelidt getidrlns(tunnelidt t)
{
	confrlnsidt idrlns;

	for (idrlns = 1; idrlns <= config->highest_rlnsid ; ++idrlns)
	{
		if (pconfigrlns[idrlns].tid == t) return idrlns;
	}

	return 0;
}

int istunneltolns(tunnelidt t)
{
	confrlnsidt idrlns;

	for (idrlns = 1; idrlns <= config->highest_rlnsid ; ++idrlns)
	{
		if (pconfigrlns[idrlns].tid == t) return 1;
	}

	return 0;
}

void calc_lac_auth(tunnelidt t, uint8_t id, uint8_t *out)
{
	MD5_CTX ctx;
	confrlnsidt idrlns;

	idrlns = getidrlns(t);

	MD5_Init(&ctx);
	MD5_Update(&ctx, &id, 1);
	MD5_Update(&ctx, pconfigrlns[idrlns].l2tp_secret, strlen(pconfigrlns[idrlns].l2tp_secret));
	MD5_Update(&ctx, pconfigrlns[idrlns].auth, 16);
	MD5_Final(out, &ctx);
}

// Forward session to external LNS
int session_forward_tolns(uint8_t *buf, int len, sessionidt sess, uint16_t proto)
{
	uint16_t t = 0, s = 0;
	uint8_t *p = buf + 2; // First word L2TP options

	s = session[sess].forwardtosession;
	if (session[s].forwardtosession != sess)
	{
		LOG(0, sess, session[sess].tunnel, "Link Session (%u) broken\n", s);
		return 0;
	}

	t = session[s].tunnel;
	if (t >= MAXTUNNEL)
	{
		LOG(1, s, t, "Session with invalid tunnel ID\n");
		return 0;
	}

	if (*buf & 0x40)
	{   // length
		p += 2;
	}

	*(uint16_t *) p = htons(tunnel[t].far); // tunnel
	p += 2;
	*(uint16_t *) p = htons(session[s].far); // session
	p += 2;

	if (*buf & 0x08)
	{   // ns/nr
		*(uint16_t *) p = htons(tunnel[t].ns); // sequence
		p += 2;
		*(uint16_t *) p = htons(tunnel[t].nr); // sequence
		p += 2;
	}

	if ((proto == PPPIP) || (proto == PPPMP) ||(proto == PPPIPV6 && config->ipv6_prefix.s6_addr[0]))
	{
		session[sess].last_packet = session[sess].last_data = time_now;
	}
	else
		session[sess].last_packet = time_now;

	tunnelsend(buf, len, t); // send it...

	return 1;
}

int addremotelns(char *mask, char *IP_RemoteLNS, char *Port_RemoteLNS, char *SecretRemoteLNS)
{
	confrlnsidt idrlns;

	for (idrlns = 1; idrlns < MAXRLNSTUNNEL; ++idrlns)
	{
		if (pconfigrlns[idrlns].state == CONFRLNSFREE)
		{
			snprintf((char *) pconfigrlns[idrlns].strmaskuser, sizeof(pconfigrlns[idrlns].strmaskuser), "%s", mask);
			pconfigrlns[idrlns].ip = ntohl(inet_addr(IP_RemoteLNS));
			pconfigrlns[idrlns].port = atoi(Port_RemoteLNS);
			snprintf((char *) pconfigrlns[idrlns].l2tp_secret, sizeof(pconfigrlns[idrlns].l2tp_secret), "%s", SecretRemoteLNS);

			config->highest_rlnsid = idrlns;

			pconfigrlns[idrlns].state = CONFRLNSSET;

			LOG(1, 0, 0, "New Remote LNS conf (count %u) mask:%s IP:%s Port:%u l2tpsecret:*****\n", idrlns,
				pconfigrlns[idrlns].strmaskuser, fmtaddr(htonl(pconfigrlns[idrlns].ip), 0),
				pconfigrlns[idrlns].port);

			return 1;
		}
	}

	LOG(0, 0, 0, "No more Remote LNS Conf Free\n");

	return 0;
}
