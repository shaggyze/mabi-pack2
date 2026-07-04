/*
 *  FAST IMPLEMENTATION OF STREAM CIPHER SNOW 2.0
 *  Synchronized with Mabinogi legacy implementation logic.
 */
#include "snow2.h"
#include <string.h>
#include "snow2tab.h"

#define byte(n,w)   (((w)>>(n*8)) & 0xff)

#define a_mul(w)    (((w)<<8) ^ snow_alpha_mul[byte(3,w)])
#define ainv_mul(w) (((w)>>8) ^ snow_alphainv_mul[byte(0,w)])

typedef enum {
    MODE_SUB = 0,
    MODE_XOR = 1,
    MODE_MODERN_BE = 2,
    MODE_MODERN_LE = 3,
    MODE_LEGACY_BE = 4,
    MODE_LEGACY_LE = 5
} Snow2Mode;

static void snow_loadkey_fast(Snow2_ctx* ctx, u32 IV3, u32 IV2, u32 IV1, u32 IV0, int mode)
{
    if (mode == MODE_MODERN_LE || mode == MODE_LEGACY_LE) {
        // Little Endian word loading
        ctx->s15=(((u32)ctx->key[3])<<24) | (((u32)ctx->key[2])<<16) | (((u32)ctx->key[1])<<8) | ((u32)ctx->key[0]);
        ctx->s14=(((u32)ctx->key[7])<<24) | (((u32)ctx->key[6])<<16) | (((u32)ctx->key[5])<<8) | ((u32)ctx->key[4]);
        ctx->s13=(((u32)ctx->key[11])<<24) | (((u32)ctx->key[10])<<16) | (((u32)ctx->key[9])<<8) | ((u32)ctx->key[8]);
        ctx->s12=(((u32)ctx->key[15])<<24) | (((u32)ctx->key[14])<<16) | (((u32)ctx->key[13])<<8) | ((u32)ctx->key[12]);
    } else {
        // Big Endian word loading — matches Mabinogi's s8 key[] sign-extension behavior
        ctx->s15=(((u32)ctx->key[0])<<24) | (((u32)ctx->key[1])<<16) | (((u32)ctx->key[2])<<8) | ((u32)ctx->key[3]);
        ctx->s14=(((u32)ctx->key[4])<<24) | (((u32)ctx->key[5])<<16) | (((u32)ctx->key[6])<<8) | ((u32)ctx->key[7]);
        ctx->s13=(((u32)ctx->key[8])<<24) | (((u32)ctx->key[9])<<16) | (((u32)ctx->key[10])<<8) | ((u32)ctx->key[11]);
        ctx->s12=(((u32)ctx->key[12])<<24) | (((u32)ctx->key[13])<<16) | (((u32)ctx->key[14])<<8) | ((u32)ctx->key[15]);
    }

    ctx->s11 =~ctx->s15;
    ctx->s10 =~ctx->s14;
    ctx->s9  =~ctx->s13;
    ctx->s8  =~ctx->s12;
    ctx->s7  = ctx->s15;
    ctx->s6  = ctx->s14;
    ctx->s5  = ctx->s13;
    ctx->s4  = ctx->s12;
    ctx->s3  =~ctx->s15;
    ctx->s2  =~ctx->s14;
    ctx->s1  =~ctx->s13;
    ctx->s0  =~ctx->s12;

    /* XOR IV values */
    ctx->s15 ^= IV0;
    ctx->s12 ^= IV1;
    ctx->s10 ^= IV2;
    ctx->s9  ^= IV3;

    ctx->r1 = 0;
    ctx->r2 = 0;

    u32 outfrom_fsm, fsmtmp;
    int clockings = (mode == MODE_LEGACY_BE || mode == MODE_LEGACY_LE) ? 1 : 2;

    /* initial clockings (Literal unroll) */
    for(int i=0; i<clockings; i++) {
        outfrom_fsm=(ctx->r1+ ctx->s15 )^ctx->r2;
        ctx->s0 =a_mul(ctx->s0 )^ ctx->s2 ^ainv_mul(ctx->s11 )^outfrom_fsm;
        fsmtmp=ctx->r2+ ctx->s5 ;
        ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
        ctx->r1=fsmtmp;

        outfrom_fsm=(ctx->r1+ ctx->s0 )^ctx->r2;
        ctx->s1 =a_mul(ctx->s1 )^ ctx->s3 ^ainv_mul(ctx->s12 )^outfrom_fsm;
        fsmtmp=ctx->r2+ ctx->s6 ;
        ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
        ctx->r1=fsmtmp;

        outfrom_fsm=(ctx->r1+ ctx->s1 )^ctx->r2;
        ctx->s2 =a_mul(ctx->s2 )^ ctx->s4 ^ainv_mul(ctx->s13 )^outfrom_fsm;
        fsmtmp=ctx->r2+ ctx->s7 ;
        ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
        ctx->r1=fsmtmp;

        outfrom_fsm=(ctx->r1+ ctx->s2 )^ctx->r2;
        ctx->s3 =a_mul(ctx->s3 )^ ctx->s5 ^ainv_mul(ctx->s14 )^outfrom_fsm;
        fsmtmp=ctx->r2+ ctx->s8 ;
        ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
        ctx->r1=fsmtmp;

        outfrom_fsm=(ctx->r1+ ctx->s3 )^ctx->r2;
        ctx->s4 =a_mul(ctx->s4 )^ ctx->s6 ^ainv_mul(ctx->s15 )^outfrom_fsm;
        fsmtmp=ctx->r2+ ctx->s9 ;
        ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
        ctx->r1=fsmtmp;

        outfrom_fsm=(ctx->r1+ ctx->s4 )^ctx->r2;
        ctx->s5 =a_mul(ctx->s5 )^ ctx->s7 ^ainv_mul(ctx->s0 )^outfrom_fsm;
        fsmtmp=ctx->r2+ ctx->s10 ;
        ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
        ctx->r1=fsmtmp;

        outfrom_fsm=(ctx->r1+ ctx->s5 )^ctx->r2;
        ctx->s6 =a_mul(ctx->s6 )^ ctx->s8 ^ainv_mul(ctx->s1 )^outfrom_fsm;
        fsmtmp=ctx->r2+ ctx->s11 ;
        ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
        ctx->r1=fsmtmp;

        outfrom_fsm=(ctx->r1+ ctx->s6 )^ctx->r2;
        ctx->s7 =a_mul(ctx->s7 )^ ctx->s9 ^ainv_mul(ctx->s2 )^outfrom_fsm;
        fsmtmp=ctx->r2+ ctx->s12 ;
        ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
        ctx->r1=fsmtmp;

        outfrom_fsm=(ctx->r1+ ctx->s7 )^ctx->r2;
        ctx->s8 =a_mul(ctx->s8 )^ ctx->s10 ^ainv_mul(ctx->s3 )^outfrom_fsm;
        fsmtmp=ctx->r2+ ctx->s13 ;
        ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
        ctx->r1=fsmtmp;

        outfrom_fsm=(ctx->r1+ ctx->s8 )^ctx->r2;
        ctx->s9 =a_mul(ctx->s9 )^ ctx->s11 ^ainv_mul(ctx->s4 )^outfrom_fsm;
        fsmtmp=ctx->r2+ ctx->s14 ;
        ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
        ctx->r1=fsmtmp;

        outfrom_fsm=(ctx->r1+ ctx->s9 )^ctx->r2;
        ctx->s10 =a_mul(ctx->s10 )^ ctx->s12 ^ainv_mul(ctx->s5 )^outfrom_fsm;
        fsmtmp=ctx->r2+ ctx->s15 ;
        ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
        ctx->r1=fsmtmp;

        outfrom_fsm=(ctx->r1+ ctx->s10 )^ctx->r2;
        ctx->s11 =a_mul(ctx->s11 )^ ctx->s13 ^ainv_mul(ctx->s6 )^outfrom_fsm;
        fsmtmp=ctx->r2+ ctx->s0 ;
        ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
        ctx->r1=fsmtmp;

        outfrom_fsm=(ctx->r1+ ctx->s11 )^ctx->r2;
        ctx->s12 =a_mul(ctx->s12 )^ ctx->s14 ^ainv_mul(ctx->s7 )^outfrom_fsm;
        fsmtmp=ctx->r2+ ctx->s1 ;
        ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
        ctx->r1=fsmtmp;

        outfrom_fsm=(ctx->r1+ ctx->s12 )^ctx->r2;
        ctx->s13 =a_mul(ctx->s13 )^ ctx->s15 ^ainv_mul(ctx->s8 )^outfrom_fsm;
        fsmtmp=ctx->r2+ ctx->s2 ;
        ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
        ctx->r1=fsmtmp;

        outfrom_fsm=(ctx->r1+ ctx->s13 )^ctx->r2;
        ctx->s14 =a_mul(ctx->s14 )^ ctx->s0 ^ainv_mul(ctx->s9 )^outfrom_fsm;
        fsmtmp=ctx->r2+ ctx->s3 ;
        ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
        ctx->r1=fsmtmp;

        outfrom_fsm=(ctx->r1+ ctx->s14 )^ctx->r2;
        ctx->s15 =a_mul(ctx->s15 )^ ctx->s1 ^ainv_mul(ctx->s10 )^outfrom_fsm;
        fsmtmp=ctx->r2+ ctx->s4 ;
        ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
        ctx->r1=fsmtmp;
    }
}

static void snow_keystream_fast(Snow2_ctx* ctx, u32 *keystream_block)
{
    u32 fsmtmp;

    ctx->s0 =a_mul(ctx->s0 )^ ctx->s2 ^ainv_mul(ctx->s11 );
    fsmtmp=ctx->r2+ ctx->s5 ;
    ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
    ctx->r1=fsmtmp;
    keystream_block[0]=(ctx->r1+ ctx->s0 )^ctx->r2^ ctx->s1 ;

    ctx->s1 =a_mul(ctx->s1 )^ ctx->s3 ^ainv_mul(ctx->s12 );
    fsmtmp=ctx->r2+ ctx->s6 ;
    ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
    ctx->r1=fsmtmp;
    keystream_block[1]=(ctx->r1+ ctx->s1 )^ctx->r2^ ctx->s2 ;

    ctx->s2 =a_mul(ctx->s2 )^ ctx->s4 ^ainv_mul(ctx->s13 );
    fsmtmp=ctx->r2+ ctx->s7 ;
    ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
    ctx->r1=fsmtmp;
    keystream_block[2]=(ctx->r1+ ctx->s2 )^ctx->r2^ ctx->s3 ;

    ctx->s3 =a_mul(ctx->s3 )^ ctx->s5 ^ainv_mul(ctx->s14 );
    fsmtmp=ctx->r2+ ctx->s8 ;
    ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
    ctx->r1=fsmtmp;
    keystream_block[3]=(ctx->r1+ ctx->s3 )^ctx->r2^ ctx->s4 ;

    ctx->s4 =a_mul(ctx->s4 )^ ctx->s6 ^ainv_mul(ctx->s15 );
    fsmtmp=ctx->r2+ ctx->s9 ;
    ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
    ctx->r1=fsmtmp;
    keystream_block[4]=(ctx->r1+ ctx->s4 )^ctx->r2^ ctx->s5 ;

    ctx->s5 =a_mul(ctx->s5 )^ ctx->s7 ^ainv_mul(ctx->s0 );
    fsmtmp=ctx->r2+ ctx->s10 ;
    ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
    ctx->r1=fsmtmp;
    keystream_block[5]=(ctx->r1+ ctx->s5 )^ctx->r2^ ctx->s6 ;

    ctx->s6 =a_mul(ctx->s6 )^ ctx->s8 ^ainv_mul(ctx->s1 );
    fsmtmp=ctx->r2+ ctx->s11 ;
    ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
    ctx->r1=fsmtmp;
    keystream_block[6]=(ctx->r1+ ctx->s6 )^ctx->r2^ ctx->s7 ;

    ctx->s7 =a_mul(ctx->s7 )^ ctx->s9 ^ainv_mul(ctx->s2 );
    fsmtmp=ctx->r2+ ctx->s12 ;
    ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
    ctx->r1=fsmtmp;
    keystream_block[7]=(ctx->r1+ ctx->s7 )^ctx->r2^ ctx->s8 ;

    ctx->s8 =a_mul(ctx->s8 )^ ctx->s10 ^ainv_mul(ctx->s3 );
    fsmtmp=ctx->r2+ ctx->s13 ;
    ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
    ctx->r1=fsmtmp;
    keystream_block[8]=(ctx->r1+ ctx->s8 )^ctx->r2^ ctx->s9 ;

    ctx->s9 =a_mul(ctx->s9 )^ ctx->s11 ^ainv_mul(ctx->s4 );
    fsmtmp=ctx->r2+ ctx->s14 ;
    ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
    ctx->r1=fsmtmp;
    keystream_block[9]=(ctx->r1+ ctx->s9 )^ctx->r2^ ctx->s10 ;

    ctx->s10 =a_mul(ctx->s10 )^ ctx->s12 ^ainv_mul(ctx->s5 );
    fsmtmp=ctx->r2+ ctx->s15 ;
    ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
    ctx->r1=fsmtmp;
    keystream_block[10]=(ctx->r1+ ctx->s10 )^ctx->r2^ ctx->s11 ;

    ctx->s11 =a_mul(ctx->s11 )^ ctx->s13 ^ainv_mul(ctx->s6 );
    fsmtmp=ctx->r2+ ctx->s0 ;
    ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
    ctx->r1=fsmtmp;
    keystream_block[11]=(ctx->r1+ ctx->s11 )^ctx->r2^ ctx->s12 ;

    ctx->s12 =a_mul(ctx->s12 )^ ctx->s14 ^ainv_mul(ctx->s7 );
    fsmtmp=ctx->r2+ ctx->s1 ;
    ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
    ctx->r1=fsmtmp;
    keystream_block[12]=(ctx->r1+ ctx->s12 )^ctx->r2^ ctx->s13 ;

    ctx->s13 =a_mul(ctx->s13 )^ ctx->s15 ^ainv_mul(ctx->s8 );
    fsmtmp=ctx->r2+ ctx->s2 ;
    ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
    ctx->r1=fsmtmp;
    keystream_block[13]=(ctx->r1+ ctx->s13 )^ctx->r2^ ctx->s14 ;

    ctx->s14 =a_mul(ctx->s14 )^ ctx->s0 ^ainv_mul(ctx->s9 );
    fsmtmp=ctx->r2+ ctx->s3 ;
    ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
    ctx->r1=fsmtmp;
    keystream_block[14]=(ctx->r1+ ctx->s14 )^ctx->r2^ ctx->s15 ;

    ctx->s15 =a_mul(ctx->s15 )^ ctx->s1 ^ainv_mul(ctx->s10 );
    fsmtmp=ctx->r2+ ctx->s4 ;
    ctx->r2=snow_T0[byte(0,ctx->r1)]^snow_T1[byte(1,ctx->r1)]^snow_T2[byte(2,ctx->r1)]^snow_T3[byte(3,ctx->r1)];
    ctx->r1=fsmtmp;
    keystream_block[15]=(ctx->r1+ ctx->s15 )^ctx->r2^ ctx->s0 ;
}

void c_snow2_loadkey_iv(u32 *state_table, const u8 *key, u32 iv0, int mode)
{
    Snow2_ctx ctx;
    ctx.keysize = 128;
    memcpy(ctx.key, key, 16);
    snow_loadkey_fast(&ctx, 0, 0, 0, iv0, (int)mode);

    state_table[0]=ctx.s15; state_table[1]=ctx.s14; state_table[2]=ctx.s13; state_table[3]=ctx.s12;
    state_table[4]=ctx.s11; state_table[5]=ctx.s10; state_table[6]=ctx.s9; state_table[7]=ctx.s8;
    state_table[8]=ctx.s7; state_table[9]=ctx.s6; state_table[10]=ctx.s5; state_table[11]=ctx.s4;
    state_table[12]=ctx.s3; state_table[13]=ctx.s2; state_table[14]=ctx.s1; state_table[15]=ctx.s0;
    state_table[16]=ctx.r1; state_table[17]=ctx.r2;
}

void c_snow2_loadkey(u32 *state_table, const u8 *key)
{
    c_snow2_loadkey_iv(state_table, key, 0, MODE_MODERN_BE);
}

void c_snow2_generate_keystream(u32 *state_table, u32 *stream)
{
    Snow2_ctx ctx;
    ctx.s15=state_table[0]; ctx.s14=state_table[1]; ctx.s13=state_table[2]; ctx.s12=state_table[3];
    ctx.s11=state_table[4]; ctx.s10=state_table[5]; ctx.s9=state_table[6]; ctx.s8=state_table[7];
    ctx.s7=state_table[8]; ctx.s6=state_table[9]; ctx.s5=state_table[10]; ctx.s4=state_table[11];
    ctx.s3=state_table[12]; ctx.s2=state_table[13]; ctx.s1=state_table[14]; ctx.s0=state_table[15];
    ctx.r1=state_table[16]; ctx.r2=state_table[17];

    snow_keystream_fast(&ctx, stream);

    state_table[0]=ctx.s15; state_table[1]=ctx.s14; state_table[2]=ctx.s13; state_table[3]=ctx.s12;
    state_table[4]=ctx.s11; state_table[5]=ctx.s10; state_table[6]=ctx.s9; state_table[7]=ctx.s8;
    state_table[8]=ctx.s7; state_table[9]=ctx.s6; state_table[10]=ctx.s5; state_table[11]=ctx.s4;
    state_table[12]=ctx.s3; state_table[13]=ctx.s2; state_table[14]=ctx.s1; state_table[15]=ctx.s0;
    state_table[16]=ctx.r1; state_table[17]=ctx.r2;
}
