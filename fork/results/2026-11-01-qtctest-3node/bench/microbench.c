#include <stdio.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec*1e-9; }
int main(void){
  unsigned char msg[65]; memset(msg, 7, sizeof msg);
  const unsigned char ctx[] = "BIP-MLDSAv2";
  OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
  if(!s){ printf("no ml-dsa-44\n"); return 1; }
  uint8_t *pk = malloc(s->length_public_key), *sk = malloc(s->length_secret_key), *sig = malloc(s->length_signature); size_t sl;
  double t=now(); for(int i=0;i<300;i++) OQS_SIG_keypair(s,pk,sk); printf("ML-DSA-44 keygen   %8.1f us/op\n",(now()-t)/300*1e6);
  t=now(); for(int i=0;i<1000;i++) OQS_SIG_sign_with_ctx_str(s,sig,&sl,msg,sizeof msg,ctx,sizeof ctx-1,sk); printf("ML-DSA-44 sign     %8.1f us/op  (sig %zu B, pk %zu B)\n",(now()-t)/1000*1e6,sl,s->length_public_key);
  int ok=0; t=now(); for(int i=0;i<5000;i++) ok+=(OQS_SIG_verify_with_ctx_str(s,msg,sizeof msg,sig,sl,ctx,sizeof ctx-1,pk)==OQS_SUCCESS); double mv=(now()-t)/5000*1e6; printf("ML-DSA-44 verify   %8.1f us/op  (ok=%d/5000)\n",mv,ok);
  secp256k1_context *c = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  unsigned char seckey[32]; for(int i=0;i<32;i++) seckey[i]=i+1; unsigned char hash[32]; memset(hash,9,32);
  secp256k1_pubkey pub; secp256k1_ecdsa_signature es; secp256k1_ec_pubkey_create(c,&pub,seckey);
  t=now(); for(int i=0;i<3000;i++) secp256k1_ecdsa_sign(c,&es,hash,seckey,NULL,NULL); printf("ECDSA sign         %8.1f us/op  (sig 64 B compact, pk 33 B)\n",(now()-t)/3000*1e6);
  ok=0; t=now(); for(int i=0;i<10000;i++) ok+=secp256k1_ecdsa_verify(c,&es,hash,&pub); double ev=(now()-t)/10000*1e6; printf("ECDSA verify       %8.1f us/op  (ok=%d/10000)\n",ev,ok);
  secp256k1_keypair kp; secp256k1_xonly_pubkey xo; unsigned char ss[64]; secp256k1_keypair_create(c,&kp,seckey); secp256k1_keypair_xonly_pub(c,&xo,NULL,&kp);
  t=now(); for(int i=0;i<3000;i++) secp256k1_schnorrsig_sign32(c,ss,hash,&kp,NULL); printf("Schnorr sign       %8.1f us/op  (sig 64 B, pk 32 B)\n",(now()-t)/3000*1e6);
  ok=0; t=now(); for(int i=0;i<10000;i++) ok+=secp256k1_schnorrsig_verify(c,ss,hash,32,&xo); double sv=(now()-t)/10000*1e6; printf("Schnorr verify     %8.1f us/op  (ok=%d/10000)\n",sv,ok);
  printf("verify ratio: ML-DSA-44 / ECDSA = %.2f, ML-DSA-44 / Schnorr = %.2f\n", mv/ev, mv/sv);
  return 0;
}
