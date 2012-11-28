/* L2TPLAC */
/* $Id: l2tplac.h,v 1.0 2012-07-01 14:49:28 fendo Exp $ */

#ifndef __L2TPLAC_H__
#define __L2TPLAC_H__

// l2tplac.c
void initremotelnsdata();
int session_forward_tolns(uint8_t *buf, int len, sessionidt sess, uint16_t proto);
int forwardtolns(sessionidt s, char * puser);
void calc_lac_auth(tunnelidt t, uint8_t id, uint8_t *out);
int istunneltolns(tunnelidt t);
int addremotelns(char *mask, char *IP_RemoteLNS, char *Port_RemoteLNS, char *SecretRemoteLNS);
#endif /* __L2TPLAC_H__ */
