/*
*  29.10.2015 - 2016
* 
* 1. For encryption is used mbedtls library.
* 2. Codec AES-256-GCM with a key length of 256/8 = 32 bytes and a length equal to iv, AES_BLOCK_SIZE = 16 bytes.
* 3. The key is formed PBKDF2-SHA512 with the number of iterations
*        from a passphrase  = (CODEC_PBKDF2_ITER + CODEC_PBKDF2_ITER_FAST),
*        from a base64      = CODEC_PBKDF2_ITER_FAST.
* 4. The page size is fixed and equal to the value SQLITE_DEFAULT_PAGE_SIZE.
* 5. The size of the backup area on the page is equal to the amount CODEC_RESERVED_SIZE.
* 6. In the reserve area stored iv length AES_BLOCK_SIZE and gcm_tag length AES_BLOCK_SIZE.
* 
* When you compile you need to set the following preprocessor directives:
* SQLITE_HAS_CODEC
* SQLITE_TEMP_STORE=2 (use memory by default but allow the PRAGMA temp_store command to overrid)
* SQLITE_DEFAULT_PAGE_SIZE=8192 (set any optional)
* SQLITE_OMIT_DEPRECATED
* 
* Notes:
* - PRAGMA KEY or PRAGMA REKEY sqlite does not check for errors!!! On errors silently return SQLITE_OK;
* - buffer is needed to encrypt (!!!you can't inplace encrypt, we need to its return, see pager_write_pagelist buffer);
* deprecaed ---> read_ctx and write_ctx are used depending on the mode (mode) in sqlite3Codec();
* deprecaed ---> write_ctx is used to write to the journal file (this gives you the ability to encrypt with a new key);
*
*---------------
* examples
*---------------
* After creating of new database file or after opening an existing encrypted database file by
*   sqlite3_open('first.db',&db);
* to specify the passphrase need:
*   sqlite3_key_v2(db, 'main', 'password', pass_length); //set codec for 'main' (or 'first.db')
* or
*   sqlite3_open_v2("file:first.db?hexkey=1234abcd",&db,SQLITE_OPEN_READWRITE|SQLITE_OPEN_URI,NULL); //hexkey in codec equal passphrase
*
* or put SQL command:
*   PRAGMA key = 'password';         // passphrase (not key)
*   PRAGMA key = 'abcdefghijklmnopqrstuvwxyz1234567890ABCDXYZ=';  //base64 43chars+'=' equal 256 bit prekey (not key)
* Further work with the database file will be executed in encrypted mode.
*
*   PRAGMA rekey = 'new password'; 
* is used to change encryption key with a new one and reencrypt database.
*   PRAGMA rekey = ''; 
* is used to decipher database file.
* 
* Attaching a file to 'main' database:
*   ATTACH DATABASE 'dbfile' AS 'alias_name' KEY 'pass';   - attaching database file
* examples:
*   ATTACH DATABASE 'new_file.db' AS 'newdb';              - attaching unencrypted database 'newdb'
*   ATTACH DATABASE 'new_file.db' AS 'newdb' KEY '';       - attaching unencrypted database 'newdb'
*   ATTACH DATABASE 'new_file.db' AS 'newdb' KEY 'pass';   - attaching encrypted database, used passphrase
*   ATTACH DATABASE 'new_file.db' AS 'newdb' KEY 'abc...z='; - attaching encrypted database, used base64 prekey
* or
*   SELECT attach('dbfile','alias_name','passphrase');
* and
*   DETACH DATABASE 'newdb';
* or
*   SELECT detach('newdb')
*
* Alternate can 
*   SELECT key(x,y)
*   SELECT rekey(x,y)
*   SELECT attach(x,y,z)
*   SELECT detach(x)
*   SELECT export(x,y)
*---------------
*/

#ifdef SQLITE_HAS_CODEC

#ifdef _DEBUG
#include <io.h>
#include <fcntl.h>

#pragma warning (disable :4996) //for open()

void debug_out(char* str)
{
	static int fd = 0; char *s = "\n\n\n//--------------------\n";
	if (!fd)
	{
		fd = open("tracelog.txt", _O_RDWR | _O_TEXT | _O_APPEND | _O_CREAT);
		write(fd, s, strlen(s));
		printf("TRACE: "); printf(s);
	}
	write(fd, str, strlen(str)); write(fd, "\n", 1);
	printf("TRACE: "); printf(str); printf("\n");
	sqlite3_free(str);
}
#define CODEC_TRACE(X) {debug_out(sqlite3_mprintf X);}
#else
#define CODEC_TRACE(X)
#endif

#if SQLITE_TEMP_STORE!=2
#pragma message(SQLITE_TEMP_STORE=2 preprocessor directive required)
#endif
#ifndef SQLITE_OMIT_DEPRECATED
#pragma message("SQLITE_OMIT_DEPRECATED" preprocessor directive required)
#endif
//-------------- header -----------------------

#include "mbedtls/entropy_poll.h"
#include "mbedtls/cipher.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"

#define SQLITE_FILE_HEADER_SZ	16
#define AES_BLOCK_SIZE			16
#define AES_MAX_KEY_SIZE		32
#define AES_IV_SIZE				AES_BLOCK_SIZE
#define GCM_TAG_SIZE			AES_BLOCK_SIZE
#define CODEC_RESERVED_SIZE		(AES_IV_SIZE + GCM_TAG_SIZE)
#define CODEC_PBKDF2_ITER		40000 //iter to get prekey from passphrase, or 0 iter to get prekey from base64 prekey
#define CODEC_PBKDF2_ITER_FAST	100   //iter to get key from prekey

typedef unsigned char byte;
int codec_token = 0;//key token for requested key (see sqlite3CodecGetKey)

typedef struct
{
	int iRef;
	int page_size;
	byte *buffer;
	byte salt[SQLITE_FILE_HEADER_SZ];
	mbedtls_cipher_context_t ctx;
} sqlCodecCTX;

void* sqlcodec_malloc(int sz);
void sqlcodec_free(void *ptr, int sz);
int sqlcodec_init(sqlCodecCTX** ptr_ctx, Db *pDb, byte* password, int len);
int sqlcodec_create(sqlCodecCTX** ptr_ctx);
void sqlcodec_destroy(sqlCodecCTX** ptr_ctx);
int sqlcodec_set_password(sqlCodecCTX* ctx, byte* pKey, int nKey);
int sqlcodec_set_buffer(sqlCodecCTX* ctx, int size);
int sqlcodec_encrypt(unsigned int page, sqlCodecCTX *ctx, byte *src, byte* dst, int size);
int sqlcodec_decrypt(unsigned int page, sqlCodecCTX *ctx, byte *src, byte* dst, int size);
//void hex2bin(const byte* hex, int sz, byte* out);
//void bin2hex(const byte* bin, int sz, byte* out);
int Base64Dec(const byte* s,int slen,byte* out,int outlen);
int Base64Enc(const byte* s,int slen, byte* out,int outlen);
int sqlcodec_copy_ctx(sqlCodecCTX** pctx_dest, sqlCodecCTX* ctx_src);
int RNG_GenerateBlock(byte* dst, int len);
int sqlcodec_rekey(sqlite3 *db, int nDb, char* zKey, int nKey);
int sqlcodec_backup(sqlite3* db, char* zDbName, int bTo, char* fileName, char* zKey, int nKey);
//void sqlcodec_exportFunc(sqlite3_context *context, int argc, sqlite3_value **argv);
//int sqlcodec_exportFull(sqlite3* db, char* fromDb, char* toDb);
//int sqlcodec_clearall(sqlite3* db, char* szDbName);
//int sqlcodec_replayAllPages(Db* pDb);

void* sqlite3Codec(void *pCodecArg, void *data, Pgno pgno, int mode);
void sqlite3FreeCodecArg(void *pCodecArg);
int sqlite3CodecAttach(sqlite3* db, int nDb, const void* zKey, int nKey);
void sqlite3CodecSizeChng(void* pCodec, int size, int reserved);
void sqlite3_activate_see(const char* in) {/*no-op*/ }

//----------------- API -----------------------------


/*
* sqlite3_key_v2
* PARGMA key='password'; //passphrase
* PARGMA key='ABCD...z=';//base64
* PRAGMA key='';
*/
SQLITE_API int SQLITE_STDCALL sqlite3_key_v2(sqlite3 *db, const char *zDbName, const void *pKey, int nKey)
{
	if (db && pKey && nKey)
	{
		int nDb = zDbName ? sqlite3FindDbName(db, zDbName) : 0;
		return sqlite3CodecAttach(db, nDb, pKey, nKey);
	}
	return SQLITE_ERROR;
}
SQLITE_API int SQLITE_STDCALL sqlite3_key(sqlite3* db, const void* pKey, int nKey) { return sqlite3_key_v2(db, NULL, pKey, nKey); }

/*
* sqlite3_rekey_v2
* PARGMA rekey='password'; //passphrase
* PARGMA rekey='ABCD...z=';//base64
* PRAGMA rekey='';
*/
SQLITE_API int SQLITE_STDCALL sqlite3_rekey_v2(sqlite3* db, const char *zDbName, void* zKey, int nKey)
{
	int nDb = zDbName ? sqlite3FindDbName(db, zDbName) : 0;
	return sqlcodec_rekey(db, nDb, (char*)zKey, nKey);
}
SQLITE_API int SQLITE_STDCALL sqlite3_rekey(sqlite3 *db, void *zKey, int nKey) { return sqlite3_rekey_v2(db, NULL, zKey, nKey); }

/*
* The function is called when you execute the
*     ATTACH x AS y KEY z;
* (also called inside VACUUM through the ATTACH '' AS 'vacuum_db';)
* If the KEY expression z is not specified, the first is called sqlite3CodecGetKey() specifies the zKey and nKey.
* If the KEY expression '' (z not set) then zKey=NULL, nKey=0 (sqlite3CodecGetKey is not called).
* NOTE:
* for empty key string '' sqlite return zKey != NULL and nKey==0, in this case, you should check the nKey.
*/
int sqlite3CodecAttach(sqlite3* db, int nDb, const void* zKey, int nKey)
{
	struct Db *pDb = &db->aDb[nDb];
	sqlCodecCTX *ctx = NULL, *src_ctx = NULL;
	int rc = SQLITE_ERROR;
	CODEC_TRACE(("sqlite3CodecAttach: start"));
	CODEC_TRACE(("  attach to nDb=%s, key='%s'", pDb->zDbSName, (char*)zKey));

	sqlite3_mutex_enter(db->mutex);

	if (nKey <= 0) { zKey = NULL; nKey = 0; }//CAST (zKey,nKey)
	if (zKey == NULL)
	{
		//without encryption resetting nReserve=0 and set codec = NULL
		if (sqlite3PagerGetCodec(sqlite3BtreePager(pDb->pBt)) != NULL)
		{
			pDb->pBt->pBt->btsFlags &= ~BTS_PAGESIZE_FIXED;//before sqlite3BtreeSetPageSize unset the BTS_PAGESIZE_FIXED flag
			sqlite3BtreeSetPageSize(pDb->pBt, sqlite3BtreeGetPageSize(pDb->pBt), 0, 0);
			sqlite3PagerSetCodec(sqlite3BtreePager(pDb->pBt), NULL, NULL, NULL, NULL);
		}
		rc = SQLITE_OK;
		CODEC_TRACE(("  warn: zKey=NULL, then codec is not installed"));
	}
	else
	{
		//If the 'main' database is encrypted and 'ATTACH x AS y', then key is taken from the 'main' database. (see attachFunc).
		//But then used codec_token.
		//If zKey == &codec_token, then key was requested from the main database
		//and for the database with number nDb initially zKey explicitly was not set
		//(so the database with the number nDb of possible unencrypted).
		if (zKey == &codec_token)
		{
			//exception: for VACUUM will be attached temporary database with name = 'vacuum_db' (see: sqlite3RunVacuum)
			if (strcmp(pDb->zDbSName, "vacuum_db") == 0)
			{
				src_ctx = (sqlCodecCTX*)sqlite3PagerGetCodec(sqlite3BtreePager(db->aDb[0].pBt));
				if (src_ctx == NULL) { CODEC_TRACE(("  error: main db unencrypted, same vacuum_db unencrypted!")); goto go_mutex_leave; }
				rc = sqlcodec_copy_ctx(&ctx, src_ctx);
				if (rc != SQLITE_OK) { CODEC_TRACE(("  error: copy ctx from main db to vacuum_db !")); goto go_mutex_leave; }
				CODEC_TRACE(("  copy to sqlCodecCTX=%X from main db to vacuum_db", ctx));
			}
			else
			{
				//on "ATTACH 'file' AS 'name'", initially password key was not set and assume that the attached database is not encrypted
				CODEC_TRACE(("  codec is not installed (the KEY is NULL)"));
				rc = SQLITE_OK;
				goto go_mutex_leave;
			}
		}
		else
		{
			//when key is setted, then init codec context
			if (sqlcodec_init(&ctx, pDb, (byte*)zKey, nKey) == SQLITE_OK) { CODEC_TRACE(("  init sqlCodecCTX=%X", ctx)); }
		}
		//setup xCodec
		sqlite3PagerSetCodec(sqlite3BtreePager(pDb->pBt), sqlite3Codec, sqlite3CodecSizeChng, sqlite3FreeCodecArg, (void*)ctx);
		//--TODO: in the future you can make a change pagesize (nReserve will remain unchanged)
		//setting pagesize и nReserve в db
		pDb->pBt->pBt->btsFlags  &= ~BTS_PAGESIZE_FIXED;//before sqlite3BtreeSetPageSize unset the BTS_PAGESIZE_FIXED flag
		sqlite3BtreeSetPageSize(pDb->pBt, ctx->page_size, CODEC_RESERVED_SIZE, 0);//iFix=0, otherwise VACUUM error: see sqlite3BtreeSetPageSize()
		//force secure delete. This has the benefit of wiping internal data when deleted
		//and also ensures that all pages are written to disk (i.e. not skipped by
		//sqlite3PagerDontWrite optimizations)
		sqlite3BtreeSecureDelete(pDb->pBt, 1);
		//if fd is null, then this is an in-memory database and
		//we dont' want to overwrite the AutoVacuum settings
		//if not null, then set to the default
		if (!sqlite3PagerIsMemdb(sqlite3BtreePager(pDb->pBt))) { sqlite3BtreeSetAutoVacuum(pDb->pBt, SQLITE_DEFAULT_AUTOVACUUM); }
		CODEC_TRACE(("sqlite3CodecAttach: end\n"));
		rc = SQLITE_OK;
		//if you have previously been trying to open an encrypted file without the key,
		//the first encrypted page of the db file will be written to the in-memory cache
		//here to clear the cache so that all pages loaded with encryption enabled
		sqlite3PagerClearCache(sqlite3BtreePager(pDb->pBt));
	}
go_mutex_leave:
	sqlite3_mutex_leave(db->mutex);
	return rc;
}

/*
* Getting key token or null when requested key.
* The function is called from SQLite (such as when you ATTACH without specifying key or with VACUUM)
*/
void sqlite3CodecGetKey(sqlite3* db, int nDb, void** zKey, int* nKey)
{
	if (sqlite3PagerGetCodec(sqlite3BtreePager(db->aDb[nDb].pBt)) != NULL) { *zKey = &codec_token; *nKey = 4; }
	else { *nKey = 0; *zKey = NULL; }
}

/*
* An implementation of the codec in the structure of Pager from pager.c
* sqlite3Codec can be called in multiple modes.
* encrypt mode - expected to return a pointer to the encrypted data without altering pData.
* decrypt mode - expected to return a pointer to pData, with the data decrypted in the input buffer.
*/
void* sqlite3Codec(void *pCodec, void *data, Pgno pgno, int mode)
{
	sqlCodecCTX *ctx = (sqlCodecCTX*)pCodec;
	int page_sz = ctx->page_size;
	byte *pData = (byte*)data;
	byte *buffer = ctx->buffer;

	if (pCodec == NULL)return data;//for unencrypted database
	switch (mode)
	{
		//decrypt
	case 0://Undo a "case 7" journal file encryption
	case 2://Reload a page
	case 3://Load a page
		if (sqlcodec_decrypt(pgno, ctx, pData, pData, page_sz))return NULL;
		return pData;
		//encrypt (return persistent buffer data, pData remains intact, see pager_write_pagelist)
	case 6://Encrypt a page for the main database file (WRITE_CTX)
	case 7://Encrypt a page for the journal file (READ_CTX) on example vacuum
		if (sqlcodec_encrypt(pgno, ctx, pData, buffer, page_sz))return NULL;
		return buffer;
	default:
		return pData;
	}
	return pData;
}
/*
* Wipe and free allocated memory for the context
*/
void sqlite3FreeCodecArg(void *pCodec)
{
	sqlCodecCTX* ctx = (sqlCodecCTX*)pCodec;
	if (ctx)sqlcodec_destroy(&ctx);
	CODEC_TRACE(("\nsqlite3FreeCodecArg:  sqlCodecCTX=%X is free\n", (char*)pCodec));
}
/*
* Notify of page size changes
*/
void sqlite3CodecSizeChng(void* pCodec, int size, int reserved)
{
	//UNDONE: sqlite3CodecSizeChng is off.  PRAGMA page_size=1024; - not work for encrypted DB !!! page_size set as SQLITE_DEFAULT_PAGE_SIZE
	//sqlcodec_set_buffer(pCodec, size);
}









//--------------- sqlcodec --------------------------
/*
* Allocate memory.
* Uses sqlite's internall malloc wrapper
*/
void* sqlcodec_malloc(int sz)
{
	void *ptr = sqlite3Malloc(sz);
#ifndef OMIT_MEMLOCK
	if (ptr)
	{
#if defined(__unix__) || defined(__APPLE__) 
		mlock(ptr, sz);
#elif defined(_WIN32)
		VirtualLock(ptr, sz);
#endif
	}
#endif
	return ptr;
}
/*
* Free and wipe memory; uses SQLites internal sqlite3_free so that memory
*/
void sqlcodec_free(void *ptr, int sz)
{
	if (ptr)
	{
		//sz = sqlite3MallocSize(ptr);//!!!not work for reason memlock
		if (sz > 0)
		{
			memset(ptr, 0, sz);
#ifndef OMIT_MEMLOCK
#if defined(__unix__) || defined(__APPLE__) 
			munlock(ptr, sz);
#elif defined(_WIN32)
			VirtualUnlock(ptr, sz);
#endif
#endif
		}
		sqlite3_free(ptr);
	}
}
/*
* Random numbers generator; return 0 (OK) || 1 (ERROR)
*/
int RNG_GenerateBlock(byte* dst, int len)
{
	size_t olen = 0; mbedtls_platform_entropy_poll(NULL, dst, len, &olen); return (olen == len ? 0: 1);
}
/*
* Codec context initialisation
*/
int sqlcodec_init(sqlCodecCTX** ptr_ctx, Db *pDb, byte* pKey, int nKey)
{
	sqlCodecCTX* ctx = NULL;

	CODEC_TRACE(("  sqlcodec_init: password='%s'", pKey));

	if (ptr_ctx == NULL)return SQLITE_ERROR;
	if (sqlcodec_create(ptr_ctx) != SQLITE_OK)return SQLITE_ERROR;
	ctx = *ptr_ctx;

	//init ctx->salt
	if (sqlite3PagerReadFileheader(sqlite3BtreePager(pDb->pBt),SQLITE_FILE_HEADER_SZ,ctx->salt) != SQLITE_OK)
	{
		if (RNG_GenerateBlock(ctx->salt, SQLITE_FILE_HEADER_SZ))return SQLITE_ERROR;
	}
	if (memcmp(ctx->salt, SQLITE_FILE_HEADER, SQLITE_FILE_HEADER_SZ) == 0)//when file unencrypted
	{
		if (RNG_GenerateBlock(ctx->salt, SQLITE_FILE_HEADER_SZ))return SQLITE_ERROR;
	}
	//init ctx->key
	if (sqlcodec_set_password(ctx, pKey, nKey) != 0)return SQLITE_ERROR;
	//init ctx->buffer and set page_size = SQLITE_DEFAULT_PAGE_SIZE
	ctx->page_size = sqlite3BtreeGetPageSize(pDb->pBt);
	if (sqlcodec_set_buffer(ctx, ctx->page_size) != SQLITE_OK)return SQLITE_ERROR;
	return SQLITE_OK;
}
/*
* Memory allocation and init codec context
*/
int sqlcodec_create(sqlCodecCTX** ptr_ctx)
{
	sqlCodecCTX* ctx = NULL;
	if (ptr_ctx == NULL)return SQLITE_ERROR; if (*ptr_ctx)sqlcodec_destroy(ptr_ctx);
	ctx = (sqlCodecCTX*)sqlcodec_malloc(sizeof(sqlCodecCTX)); if (ctx == NULL)return SQLITE_NOMEM;
	memset(ctx, 0, sizeof(sqlCodecCTX)); ctx->iRef = 1;
	*ptr_ctx = ctx;
	return SQLITE_OK;
}
/*
* Free codec context
*/
void sqlcodec_destroy(sqlCodecCTX** ptr_ctx)
{
	sqlCodecCTX* ctx;
	if (ptr_ctx == NULL)return;
	ctx = *ptr_ctx;
	if (ctx)
	{
		ctx->iRef--;
		if (ctx->iRef <= 0)
		{
			sqlcodec_set_buffer(ctx, 0);
			mbedtls_cipher_free(&ctx->ctx);
			sqlcodec_free(ctx, sizeof(sqlCodecCTX));
		}
	}
	*ptr_ctx = NULL;
}
/*
* Setting page_size and buffer of codec context
*/
int sqlcodec_set_buffer(sqlCodecCTX* ctx, int size)
{
	if (size == 0) { sqlcodec_free(ctx->buffer, ctx->page_size); ctx->page_size = 0; ctx->buffer = NULL; return SQLITE_OK; }
	if (ctx->buffer==NULL || ctx->page_size != size) { if ((ctx->buffer = (byte*)sqlcodec_malloc(size)) == NULL) { return SQLITE_NOMEM; }ctx->page_size = size; }
	return SQLITE_OK;
}
/*
* Setting new key for codec context
* if nKey>0, then pKey is passphrase or base64 prekey, then
*    prekey=PBKDF2(passphrase, salt, CODEC_PBKDF2_ITER) (if pKey is passphrase)
*    prekey=base64prekey  (if pKey is base64 prekey)
* and
*    key=PBKDF2(prekey, salt, CODEC_PBKDF2_ITER_FAST)
*
* NOTES:
* - hex key not work: when ATTACH 'file' AS 'alias' KEY X'abcd', then sqlite convert hex to blob and pKey not hex string
* - the last character in the base64 prekey is '=' because the key length is not divisible by 3
*/
int sqlcodec_set_password(sqlCodecCTX* ctx, byte* pKey, int nKey)
{
	byte key[AES_MAX_KEY_SIZE];
	if (ctx == NULL) { CODEC_TRACE(("  error: ctx=NULL")); return SQLITE_ERROR; }
	if (nKey <= 0) { CODEC_TRACE(("  error: undefined password key for sqlCodecCTX=%X", ctx)); return SQLITE_ERROR; }

	//detecting pKey is base64 prekey
	if(Base64Dec(pKey,nKey,key,AES_MAX_KEY_SIZE)!=AES_MAX_KEY_SIZE)
	{
		//prekey derivation from passphrase
		mbedtls_md_context_t md_ctx; mbedtls_md_init(&md_ctx);
		if (mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 1))return SQLITE_NOMEM;
		if (mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, pKey, nKey, ctx->salt, sizeof(ctx->salt), CODEC_PBKDF2_ITER, sizeof(key), key))return SQLITE_NOMEM;
		mbedtls_md_free(&md_ctx);
	}

	{
		//fast key generation for full key
		mbedtls_md_context_t md_ctx; mbedtls_md_init(&md_ctx);
		if (mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 1))return SQLITE_NOMEM;
		if (mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, key, sizeof(key), ctx->salt, sizeof(ctx->salt), CODEC_PBKDF2_ITER_FAST, sizeof(key), key))return SQLITE_NOMEM;
		mbedtls_md_free(&md_ctx);
	}
	//init ctx structure
	mbedtls_cipher_init(&ctx->ctx);
	mbedtls_cipher_setup(&ctx->ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM));
	mbedtls_cipher_set_padding_mode(&ctx->ctx, MBEDTLS_PADDING_NONE);
	mbedtls_cipher_setkey(&ctx->ctx, key, (AES_MAX_KEY_SIZE)<<3, MBEDTLS_ENCRYPT);

	CODEC_TRACE(("  sqlcodec_set_password: key='%s'", pKey));

	memset(key, 0, sizeof(key));
	return SQLITE_OK;
}
/*
* Copy codec context
*/
int sqlcodec_copy_ctx(sqlCodecCTX** pctx_dest, sqlCodecCTX* ctx_src)
{
	if (ctx_src != NULL)
	{
		*pctx_dest = ctx_src; ctx_src->iRef++;
		return SQLITE_OK;
	}
	return SQLITE_ERROR;
}
/*
* Auxillary functions
*/
//int hexsym2int(char c) { return (c >= '0' && c <= '9') ? (c)-'0' : (c >= 'A'&& c <= 'F') ? (c)-'A' + 10 : (c >= 'a' && c <= 'f') ? (c)-'a' + 10 : 0; }
//void hex2bin(const byte* hex, int sz, byte* out) { int len = sz - (sz & 1), i; for (i = 0; i < len; i += 2) { out[i / 2] = (hexsym2int(hex[i]) << 4) | hexsym2int(hex[i + 1]); }if (sz & 1)out[i / 2] = hexsym2int(hex[i]); }
//void bin2hex(const byte* bin, int sz, byte* out) { byte ch[17] = { "0123456789abcdef" };int i, c; for (i = 0; i < sz; i++) { c = (byte)bin[i]; out[i * 2 + 0] = ch[(c >> 4) & 0xF]; out[i * 2 + 1] = ch[c & 0xF]; } }
//encoding blob to base64 character array
//s    - input blob (byte array),
//slen - length of s,
//out  - output character array (without terminating character '\0'),
//       output length = int((slen+2)/3)*4,
//outlen - output array length,
//returns
//      the number of characters actually written to the output array
//      or -1 on error.
int Base64Enc(const unsigned char* s,int slen,unsigned char* out,int outlen)
{
	const static unsigned char* codesym="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	unsigned int c,count=slen/3;int len=(slen+2)/3*4;
	if(slen<=0 || outlen<=0 || outlen<len)return-1;	
	while(count--)
	{
		c=*s++;c<<=8;c|=*s++;c<<=8;c|=*s++;					
		*out++=codesym[(c>>18)&0x3F];
		*out++=codesym[(c>>12)&0x3F];
		*out++=codesym[(c>>6)&0x3F];
		*out++=codesym[(c)&0x3F];
	}
	if(slen%3 == 2)
	{
		c=*s++;c<<=8;c|=*s++;c<<=8;
		*out++=codesym[(c>>18)&0x3F];
		*out++=codesym[(c>>12)&0x3F];
		*out++=codesym[(c>>6)&0x3F];
		*out='=';
	}
	else if(slen%3 == 1)
	{
		c=*s;c<<=16;
		*out++=codesym[(c>>18)&0x3F];
		*out++=codesym[(c>>12)&0x3F];
		*out++='=';
		*out='=';
	}
	return len;
}
//decoding base64 character array to blob (byte array)
//s    - input base64 character array (can include '\r','\n',' '),
//slen - length of s,
//out  - output byte array,
//       output length = s_len_without_spaces/4*3-num_eq,
//         s_len_without_spaces - length s without space characters, divisible by 4,
//         num_eq - the number of tail symbols '=',
//       out may be the same as s (inplace),
//outlen - out array length,
//returns
//      the number of characters actually written to the output array
//      or -1 on error.
int Base64Dec(const unsigned char* s,int slen,unsigned char* out,int outlen)
{
	const static unsigned char symdec[] = {
	127,127,127,127,127,127,127,127,127,127,127,127,127,127,127,127,
	127,127,127,127,127,127,127,127,127,127,127,127,127,127,127,127,
	127,127,127,127,127,127,127,127,127,127,127, 62,127,127,127, 63,
	 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,127,127,127,  0,127,127,
	127,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,127,127,127,127,127,
	127, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,127,127,127,127,127};
	unsigned int c;int len=0;unsigned char a,b,a0,a1;
	unsigned char* s_end=(unsigned char*)s+slen;
	if(slen<=0 || outlen<=0)return -1;
	while(1)
	{
		while(s<s_end && (*s=='\r' || *s=='\n' || *s==' '))s++;if(s==s_end)break;
		a=*s++;if(a>127)return-1;b=symdec[a];if(b>63)return-1;c=b;c<<=6;
		while(s<s_end && (*s=='\r' || *s=='\n' || *s==' '))s++;if(s==s_end)return-1;
		a=*s++;if(a>127)return-1;b=symdec[a];if(b>63)return-1;c|=b;c<<=6;
		while(s<s_end && (*s=='\r' || *s=='\n' || *s==' '))s++;if(s==s_end)return-1;
		a=*s++;if(a>127)return-1;b=symdec[a];if(b>63)return-1;c|=b;c<<=6;a0=a;
		while(s<s_end && (*s=='\r' || *s=='\n' || *s==' '))s++;if(s==s_end)return-1;
		a=*s++;if(a>127)return-1;b=symdec[a];if(b>63)return-1;c|=b;a1=a;

		if(a0=='=' && a1!='=')return-1;
		if(a0=='='||a1=='=')
		{
			if(len>=outlen)return-1;						
			*out++=c>>16;len++;
			if(a0!='='){if(len>=outlen)return-1;*out++=c>>8;len++;}
			while(s<s_end && (*s=='\r' || *s=='\n' || *s==' '))s++;if(s==s_end)break;
			return-1;
		}
		else
		{
			if(len+3>outlen)return-1;			
			*out++=c>>16;
			*out++=c>>8;
			*out++=c;
			len+=3;
		}
	}
	return len;
}






/*
* Encryption function
* On sucess returns 0, otherwise non-zero
*/
int sqlcodec_encrypt(unsigned int page, sqlCodecCTX *ctx, byte *src, byte* dst, int size)
{
	int len, rc; const int offset = SQLITE_FILE_HEADER_SZ; size_t olen;
	//if (ctx->ctx.key_bitlen == 0){ memcpy(dst, src, size); return 0; } //nothing to encrypt
	if (page == 1) { memcpy(dst, ctx->salt, offset); src += offset; dst += offset; size -= offset; }
	len = size - CODEC_RESERVED_SIZE;
	rc  = RNG_GenerateBlock(dst + len, AES_IV_SIZE);
	rc |= mbedtls_cipher_auth_encrypt(&ctx->ctx, dst + len, AES_IV_SIZE, (byte*)&page, sizeof(page), src, len, dst, &olen, dst + len + AES_IV_SIZE, GCM_TAG_SIZE);
	if (rc != 0){ if(page == 1){dst-=offset;size+=offset;} memset(dst, 0, size); }
	CODEC_TRACE(("  encrypt %s: page=%i, size=%i", rc==0?"OK":"ERROR", page, size));
	return rc;
}
/*
* Decryption function
* On sucess returns 0, otherwise non-zero
*/
int sqlcodec_decrypt(unsigned int page, sqlCodecCTX *ctx, byte *src, byte* dst, int size)
{
	int len, rc; const int offset = SQLITE_FILE_HEADER_SZ; size_t olen;
	//if (ctx->ctx.key_bitlen == 0) { return 0; }
	if (page == 1) { memcpy(dst, zMagicHeader, offset); src += offset; dst += offset; size -= offset; }
	len = size - CODEC_RESERVED_SIZE;
	rc = mbedtls_cipher_auth_decrypt(&ctx->ctx, dst + len, AES_IV_SIZE, (byte*)&page, sizeof(page), src, len, dst, &olen, dst + len + AES_IV_SIZE, GCM_TAG_SIZE);
	memset(src+len, 0, CODEC_RESERVED_SIZE);
	if (rc != 0 && page == 1){ memset(dst-offset, 0, offset); }//clear zMagicHeader
	CODEC_TRACE(("  decrypt %s: page=%i, size=%i", rc == 0 ? "OK" : "ERROR", page, size));
	return rc;
}

























/*
* This is copy of execSql and execSqlF.
*/
int sqlcodec_execSql(sqlite3 *db, char **pzErrMsg, const char *zSql)
{
  sqlite3_stmt *pStmt;
  int rc;

  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if( rc!=SQLITE_OK ) return rc;
  while( SQLITE_ROW==(rc = sqlite3_step(pStmt)) ){
    const char *zSubSql = (const char*)sqlite3_column_text(pStmt,0);
    assert( sqlite3_strnicmp(zSql,"SELECT",6)==0 );
    if( zSubSql ){
      assert( zSubSql[0]!='S' );
      rc = sqlcodec_execSql(db, pzErrMsg, zSubSql);
      if( rc!=SQLITE_OK ) break;
    }
  }
  assert( rc!=SQLITE_ROW );
  if( rc==SQLITE_DONE ) rc = SQLITE_OK;
  if( rc ){
    sqlite3SetString(pzErrMsg, db, sqlite3_errmsg(db));
  }
  (void)sqlite3_finalize(pStmt);
  return rc;
}
int sqlcodec_execSqlF(sqlite3 *db, char **pzErrMsg, const char *zSql, ...)
{
  char *z;
  va_list ap;
  int rc;
  va_start(ap, zSql);
  z = sqlite3VMPrintf(db, zSql, ap);
  va_end(ap);
  if( z==0 ) return SQLITE_NOMEM;
  rc = sqlcodec_execSql(db, pzErrMsg, z);
  sqlite3DbFree(db, z);
  return rc;
}

#if 0
/*
*Clear attached database
*used in sqlcodec_exportFull
*/
int sqlcodec_clearall(sqlite3* db, char* szDbName)
{
	int rc = SQLITE_OK;     /* Return code from service routines */
	char *pzErrMsg = NULL;

	rc = sqlcodec_execSqlF(db, &pzErrMsg,
		"SELECT 'DROP TABLE IF EXISTS \"%w\".' || quote(name)"
		" FROM \"%w\".sqlite_master"
		" WHERE type='table'",
		szDbName, szDbName
	);
	if( rc!=SQLITE_OK ) return rc;
	rc = sqlcodec_execSqlF(db, &pzErrMsg,
		"SELECT 'DROP INDEX IF EXISTS \"%w\".' || quote(name)"
		" FROM \"%w\".sqlite_master"
		" WHERE type='index'",
		szDbName, szDbName
	);
	if( rc!=SQLITE_OK ) return rc;
	rc = sqlcodec_execSqlF(db, &pzErrMsg,
		"SELECT 'DROP VIEW IF EXISTS \"%w\".' || quote(name)"
		" FROM \"%w\".sqlite_master"
		" WHERE type='view'",
		szDbName, szDbName
	);
	if( rc!=SQLITE_OK ) return rc;
	rc = sqlcodec_execSqlF(db, &pzErrMsg,
		"SELECT 'DROP TRIGGER IF EXISTS \"%w\".' || quote(name)"
		" FROM \"%w\".sqlite_master"
		" WHERE type='trigger'",
		szDbName, szDbName
	);
	return rc;
}
#endif

/*
* Export entries from attached database with name in fromDb to attached database with name in toDb.
* Before export the attached database toDb will be cleared.
* Based on sqlite3RunVacuum from vacuum.c
*/
int sqlcodec_exportFull(sqlite3* db, char* fromDb, char* toDb)
{
	int rc = SQLITE_OK;     /* Return code from service routines */
	Btree *pFrom;           /* The database being vacuumed */
	Btree *pTo;             /* The temporary database we vacuum into */
	int saved_flags;        /* Saved value of the db->flags */
	int saved_nChange;      /* Saved value of db->nChange */
	int saved_nTotalChange; /* Saved value of db->nTotalChange */
	u8 saved_mTrace;		/* Saved db->mTrace */
	char *pzErrMsg = NULL;
	int nFrom = sqlite3FindDbName(db, fromDb);
	int nTo = sqlite3FindDbName(db, toDb);

	if (nFrom<0 || nTo<0) { return SQLITE_ERROR; }

	if (!db->autoCommit) {
		return SQLITE_ERROR;
	}
	if (db->nVdbeActive > 1) {
		return SQLITE_ERROR;
	}

	pFrom = db->aDb[nFrom].pBt;
	pTo = db->aDb[nTo].pBt;

	CODEC_TRACE(("start sqlcodec_exportFull: fromDb=%s, toDb=%s", fromDb, toDb));

	// force clear toDb
	sqlite3BtreeEnter(pTo);
	pager_truncate(sqlite3BtreePager(pTo), 0);
	sqlite3BtreeEnterAll(db);
	sqlite3ResetOneSchema(db, nTo);
	sqlite3BtreeLeaveAll(db);
	sqlite3BtreeLeave(pTo);

	//clear attached database
	//rc = sqlcodec_clearall(db, toDb);
	//if( rc!=SQLITE_OK ) return rc;

	// Save the current value of the database flags so that it can be
	// restored before returning. Then set the writable-schema flag, and
	// disable CHECK and foreign key constraints.
	saved_flags = db->flags;
	saved_nChange = db->nChange;
	saved_nTotalChange = db->nTotalChange;
	saved_mTrace = db->mTrace;
	db->flags |= (SQLITE_WriteSchema | SQLITE_IgnoreChecks
		          | SQLITE_PreferBuiltin | SQLITE_Vacuum);
	db->flags &= ~(SQLITE_ForeignKeys | SQLITE_ReverseOrder | SQLITE_CountRows);
	db->mTrace = 0;


	pFrom = db->aDb[nFrom].pBt;
	pTo = db->aDb[nTo].pBt;
	sqlite3BtreeSetCacheSize(pTo, db->aDb[nFrom].pSchema->cache_size);
	sqlite3BtreeSetSpillSize(pTo, sqlite3BtreeSetSpillSize(pFrom,0));
	sqlite3BtreeSetPagerFlags(pTo, PAGER_SYNCHRONOUS_OFF|PAGER_CACHESPILL);

	// Query the schema of the fromDb database. Create a mirror schema
	// in the temporary database.
	db->init.iDb = nTo; /* force new CREATE statements into toDb */
	rc = sqlcodec_execSqlF(db, &pzErrMsg,
		"SELECT sql FROM \"%w\".sqlite_master"
		" WHERE type='table' AND name<>'sqlite_sequence'"
		" AND coalesce(rootpage,1)>0",
		fromDb
	);
	if( rc!=SQLITE_OK ) goto end_of_export;
	rc = sqlcodec_execSqlF(db, &pzErrMsg,
		"SELECT sql FROM \"%w\".sqlite_master"
		" WHERE type='index' AND length(sql)>10",
		fromDb
	);
	if( rc!=SQLITE_OK ) goto end_of_export;
	db->init.iDb = 0;

	// Loop through the tables in the main database. For each, do
	// an "INSERT INTO vacuum_db.xxx SELECT * FROM main.xxx;" to copy
	// the contents to the temporary database.
	rc = sqlcodec_execSqlF(db, &pzErrMsg,
		"SELECT 'INSERT INTO \"%w\".'||quote(name)"
		"||' SELECT * FROM \"%w\".'||quote(name)"
		"FROM \"%w\".sqlite_master "
		"WHERE type='table' AND coalesce(rootpage,1)>0",
		toDb, fromDb, toDb
	);
	assert( (db->flags & SQLITE_Vacuum)!=0 );
	db->flags &= ~SQLITE_Vacuum;
	if( rc!=SQLITE_OK ) goto end_of_export;

	// Copy the triggers, views, and virtual tables from the main database
	// over to the temporary database.  None of these objects has any
	// associated storage, so all we have to do is copy their entries
	// from the SQLITE_MASTER table.
	rc = sqlcodec_execSqlF(db, &pzErrMsg,
		"INSERT INTO \"%w\".sqlite_master"
		" SELECT * FROM \"%w\".sqlite_master"
		" WHERE type IN('view','trigger')"
		" OR(type='table' AND rootpage=0)",
		toDb, fromDb
	);
  
end_of_export:
	db->init.iDb = 0;
	db->flags = saved_flags;
	db->nChange = saved_nChange;
	db->nTotalChange = saved_nTotalChange;
	db->mTrace = saved_mTrace;
	return rc;
}

/*
* test database pages to validation
*/
int sqlcodec_replayAllPages(Db* pDb)
{
	int rc = SQLITE_OK;
	sqlite3PagerClearCache(sqlite3BtreePager(pDb->pBt));
	{
		int page_count = -1;
		Pgno pgno; PgHdr *page;
		Pager *pPager = sqlite3BtreePager(pDb->pBt);
		Pgno nSkip = PENDING_BYTE_PAGE(pPager);

		sqlite3PagerPagecount(pPager, &page_count);
		for (pgno = 1; rc == SQLITE_OK && pgno <= (unsigned int)page_count; pgno++)
		{
			if (pgno == nSkip)continue;//skip this page (see pager.c:pagerAcquire for reasoning)
			rc = sqlite3PagerGet(pPager, pgno, &page, 0);

			if (rc != SQLITE_OK)break;
			if (rc == SQLITE_OK)
			{//write page see pager_incr_changecounter for example
				//rc = sqlite3PagerWrite(page);
				if (rc == SQLITE_OK)sqlite3PagerUnref(page);
			}
		}
	}
	return rc;
}

/*
* Reencrypt database number Db with or without key.
* When all OK, then return SQLITE_OK.
* When error, then return error code.
* If error code = SQLITE_CORRUPT and database rollback failed,
*                 then main database will not restored !!!
* if PRAGMA rekey, then sqlite does not check for errors !!!
*/
int sqlcodec_rekey(sqlite3 *db, int nDb, char* zKey, int nKey)
{
	int i, rc;
	Db *pDb = &db->aDb[nDb];
	sqlCodecCTX* ctx = (sqlCodecCTX*)sqlite3PagerGetCodec(sqlite3BtreePager(pDb->pBt));

	//CAST(zKey,nKey)
	if (nKey <= 0) { zKey = NULL; nKey = 0; };
	//if the database is not encrypted, and new key is not set, do nothing
	if (ctx == NULL && zKey == NULL)return SQLITE_OK;
	//NOTE: PAGE-BY-PAGE CONVERSION IS NOT BE ABLE TO DO IT because nReserve>0.

	//if (ctx == NULL || zKey == NULL)
	{
		//will create a temporary random password for backup file, format base64
		byte base64prekey[((AES_MAX_KEY_SIZE)+2)/3*4+1];RNG_GenerateBlock(base64prekey+sizeof(base64prekey)-AES_MAX_KEY_SIZE,AES_MAX_KEY_SIZE);if(Base64Enc(base64prekey+sizeof(base64prekey)-AES_MAX_KEY_SIZE,AES_MAX_KEY_SIZE,base64prekey,sizeof(base64prekey)-1)==-1){CODEC_TRACE(("ATTENTION rekey ERROR !!!"));return SQLITE_NOMEM;}base64prekey[sizeof(base64prekey)-1]=0;
		//backup database to encrypted temporary file
		rc = sqlcodec_backup(db, pDb->zDbSName, 1, "vacuum_0000.tmp", (char*)base64prekey, sizeof(base64prekey)-1);
		//restore from backup with zKey
		if (rc == SQLITE_OK)
		{
			sqlite3_mutex_enter(db->mutex);
			sqlite3BtreeEnter(pDb->pBt);
			for (i = 0; i < 3; i++)
			{
				//force clear attached database
				pager_truncate(sqlite3BtreePager(pDb->pBt), 0);
				sqlite3BtreeEnterAll(db);
				sqlite3ResetOneSchema(db, nDb);
				sqlite3BtreeLeaveAll(db);
				if (ctx)sqlite3BtreePager(pDb->pBt)->xCodecFree = NULL;//save ctx
				if (i == 0)
				{
					rc = sqlite3CodecAttach(db, nDb, zKey, nKey);
					if (rc != SQLITE_OK)continue;
					rc = sqlcodec_backup(db, pDb->zDbSName, 2, "vacuum_0000.tmp", (char*)base64prekey, sizeof(base64prekey)-1);
					if (rc != SQLITE_OK)continue;
					if (ctx) { sqlite3FreeCodecArg(ctx); }//free ctx
					//reset shema, otherwise after rekey prepare returns error: no such table (table is VIEW AS SELECT * FROM TEST)
					sqlite3BtreeEnterAll(db);
					sqlite3ResetOneSchema(db, nDb);
					sqlite3BtreeLeaveAll(db);
					break;
				}

				//try to restore database with old codec
				//free new codec
				rc = sqlite3CodecAttach(db, nDb, NULL, 0);
				//restore old codec
				if (ctx)
				{
					rc = sqlite3CodecAttach(db, nDb, "###########################################=", 44);
					if (rc == SQLITE_OK)
					{
						void* ctx2 = sqlite3BtreePager(pDb->pBt)->pCodec;
						if(ctx2)sqlite3FreeCodecArg(ctx2);
						sqlite3BtreePager(pDb->pBt)->pCodec = ctx;
					}
				}
				if (rc != SQLITE_OK)continue;
				rc = sqlcodec_backup(db, pDb->zDbSName, 2, "vacuum_0000.tmp", (char*)base64prekey, sizeof(base64prekey)-1);
				if (rc == SQLITE_OK)break;
			}
			if (rc != SQLITE_OK || i > 0)rc = SQLITE_CORRUPT;
			sqlite3BtreeLeave(pDb->pBt);
			sqlite3_mutex_leave(db->mutex);
		}
		sqlite3OsDelete(db->pVfs, "vacuum_0000.tmp", 1);
		memset(base64prekey, 0, sizeof(base64prekey));
		if(rc!=SQLITE_OK){CODEC_TRACE(("ATTENTION: rekey ERROR !!!"));}
		return rc;
	}

	//reencrypt database with new zKey
#if 0
	{
		byte oldsalt[SQLITE_FILE_HEADER_SZ];

		CODEC_TRACE(("sqlite3rekey_v2: start"));

		//TODO: salt is only used to generate the key and read/write the 1st page, but for encrypting or decrypting not being used 
		//generate new salt and set new password and salt for only write ctx
		memcpy(oldsalt, ctx->salt_pass, SQLITE_FILE_HEADER_SZ);
		if (RNG_GenerateBlock(ctx->salt_pass, SQLITE_FILE_HEADER_SZ))return SQLITE_ERROR;
		sqlcodec_set_password(ctx, (nKey == 0 && *((byte*)zKey) == '\0') ? NULL : zKey, nKey, CODEC_WRITE_CTX);

		sqlite3_mutex_enter(db->mutex);
		// do stuff here to rewrite the database 
		// 1. Create a transaction on the database
		// 2. Iterate through each page, reading it and then writing it.
		// 3. If that goes ok then commit and put ctx->rekey into ctx->key
		//    note: don't deallocate rekey since it may be used in a subsequent iteration 
		rc = sqlite3BtreeBeginTrans(pDb->pBt, 1);//begin write transaction (wrflag=1)
		if (rc == SQLITE_OK)
		{
			int page_count = -1;
			Pgno pgno; PgHdr *page;
			Pager *pPager = sqlite3BtreePager(pDb->pBt);
			Pgno nSkip = PENDING_BYTE_PAGE(pPager);

			sqlite3PagerPagecount(pPager, &page_count);
			for (pgno = 1; rc == SQLITE_OK && pgno <= (unsigned int)page_count; pgno++)
			{
				if (pgno == nSkip)continue;//skip this page (see pager.c:pagerAcquire for reasoning)
				rc = sqlite3PagerGet(pPager, pgno, &page);

				if (rc == SQLITE_OK)
				{//write page see pager_incr_changecounter for example
					rc = sqlite3PagerWrite(page);
					if (rc == SQLITE_OK)sqlite3PagerUnref(page);
				}
			}
		}
		//if commit was successful commit and copy the rekey data to current key, else rollback to release locks
		if (rc == SQLITE_OK)
		{
			rc = sqlite3BtreeCommit(pDb->pBt);
			//sqlcodec_set_password(ctx, ctx->ctx_write.key, 0, CODEC_READ_CTX);
			CODEC_TRACE(("  OK and commit"));
		}
		else
		{
			sqlite3BtreeRollback(pDb->pBt, SQLITE_ABORT_ROLLBACK, 0);
			memcpy(ctx->salt_pass, oldsalt, SQLITE_FILE_HEADER_SZ);//restore old salt
			sqlcodec_set_password(ctx, ctx->ctx_read.key, 0, CODEC_WRITE_CTX);//restore ctx
			CODEC_TRACE(("  ERROR and rollback"));
		}
		sqlite3_mutex_leave(db->mutex);
		CODEC_TRACE(("sqlite3rekey_v2: end"));
		return rc;
	}
#endif
}


/*
* Backup database to/from disk file with encryption by zKey
* if bTo = 1 - then db -> file with zKey
* if bTo = 0 - then db <- file with zKey
* if zKey is not null, then it used, otherwise backup without encryption
*/
int sqlcodec_backup(sqlite3* db, char* zDbName, int bTo, char* fileName, char* zKey, int nKey)
{
	Db* pDb1, *pDb2;
	int nDb1, nDb2, rc;
	char* zSql = NULL;

	//CAST(zKey,nKey)
	if (nKey <= 0) { zKey = NULL; nKey = 0; }
	if (fileName == NULL)return SQLITE_ERROR;
	if (bTo == 1)sqlite3OsDelete(db->pVfs, fileName, 1);
	zSql = sqlite3_mprintf("ATTACH \"%w\" AS 'vacuum_0000' KEY \"%w\"", fileName, zKey);
	rc = (zSql == NULL) ? SQLITE_NOMEM : sqlite3_exec(db, zSql, NULL, 0, NULL);
	sqlite3_free(zSql);
	if (rc != SQLITE_OK) return rc;

	nDb1 = sqlite3FindDbName(db, zDbName); if (nDb1 < 0)return SQLITE_ERROR;
	nDb2 = sqlite3FindDbName(db, "vacuum_0000"); if (nDb2 < 0)return SQLITE_ERROR;
	pDb1 = &db->aDb[nDb1];
	pDb2 = &db->aDb[nDb2];

	sqlite3_mutex_enter(db->mutex);
	sqlite3BtreeEnter(pDb1->pBt);
	sqlite3BtreeEnter(pDb2->pBt);
	if (rc == SQLITE_OK)
	{
		if (bTo == 1)
		{
			rc = sqlcodec_exportFull(db, pDb1->zDbSName, pDb2->zDbSName);//copy 1->2
			if (rc == SQLITE_OK)rc = sqlcodec_replayAllPages(pDb2);//test new db
		}
		else //bTo == 2
		{
			rc = sqlcodec_exportFull(db, pDb2->zDbSName, pDb1->zDbSName);//copy 2->1
			if (rc == SQLITE_OK)rc = sqlcodec_replayAllPages(pDb1);//test new db
		}
	}
	sqlite3BtreeLeave(pDb2->pBt);
	sqlite3BtreeLeave(pDb1->pBt);
	sqlite3_mutex_leave(db->mutex);

	sqlite3_exec(db, "DETACH vacuum_0000", NULL, 0, NULL);
	if (rc != SQLITE_OK && bTo == 1) sqlite3OsDelete(db->pVfs, fileName, 1);
	return rc;
}














/*
* Implementation of an "export" function that allows a caller
* to duplicate the main database to an attached database. This is intended
* as a conveneince for users who need to:
*
*   1. migrate from an non-encrypted database to an encrypted database
*   2. move from an encrypted database to a non-encrypted database
*   3. convert beween the various flavors of encrypted databases.
*
* This implementation is based heavily on the procedure and code used
* in vacuum.c, but is exposed as a function that allows export to any
* named attached database.
*
* Copy database and schema from the main database to an attached database
* Based on sqlite3RunVacuum from vacuum.c
*
* sqlite3_create_function(db, "export", 1, SQLITE_UTF8, NULL, &sqlcodec_exportFunc, NULL, NULL);
* and used as:
* ATTACH 'fileDb.sqlite' AS 'newDb' KEY 'password'
* or
* ATTACH 'fileDb.sqlite' AS 'newDb'
* then
* SELECT export('fromDb','newDb');
*/
void sqlcodec_export_function(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	int rc = SQLITE_OK;     /* Return code from service routines */
	Btree *pFrom;           /* The database being vacuumed */
	Btree *pTo;             /* The temporary database we vacuum into */
	int saved_flags;        /* Saved value of the db->flags */
	int saved_nChange;      /* Saved value of db->nChange */
	int saved_nTotalChange; /* Saved value of db->nTotalChange */
	u8 saved_mTrace;		/* Saved db->mTrace */
	char *pzErrMsg = NULL;
	char *fromDb, *toDb;
	int nFrom, nTo;

	sqlite3 *db = sqlite3_context_db_handle(context);

	if (!db->autoCommit) {
		sqlite3SetString(&pzErrMsg, db, "cannot export from within a transaction");
		sqlite3_result_error(context, pzErrMsg, -1);
		sqlite3DbFree(db, pzErrMsg);
		return;
	}
	if (db->nVdbeActive > 1) {
		sqlite3SetString(&pzErrMsg, db, "cannot export - SQL statements in progress");
		sqlite3_result_error(context, pzErrMsg, -1);
		sqlite3DbFree(db, pzErrMsg);
		return;
	}

	fromDb=(char*)sqlite3_value_text(argv[0]);
	toDb = (char*)sqlite3_value_text(argv[1]);
	nFrom = sqlite3FindDbName(db, fromDb);
	nTo = sqlite3FindDbName(db, toDb);

	if (nFrom<0 || nTo<0) {
		sqlite3SetString(&pzErrMsg, db, "cannot Export - attached database error");
		sqlite3_result_error(context, pzErrMsg, -1);
		sqlite3DbFree(db, pzErrMsg);
		return;
	}
	pFrom = db->aDb[nFrom].pBt;
	pTo = db->aDb[nTo].pBt;

	CODEC_TRACE(("start sqlcodec_exportFunc: fromDb=%s, toDb=%s", fromDb, toDb));

	//force clear attached database
	sqlite3BtreeEnter(pTo);
	pager_truncate(sqlite3BtreePager(pTo), 0);
	sqlite3BtreeEnterAll(db);
	sqlite3ResetOneSchema(db, nTo);
	sqlite3BtreeLeaveAll(db);
	sqlite3BtreeLeave(pTo);


	//!!! this not work, returns error: table in the database is locked, try sqlite3BtreeEnter
	//rc = sqlcodec_clearall(db, toDb);
	//if( rc!=SQLITE_OK )
	//{
	//	sqlite3SetString(&pzErrMsg, db, "cannot Export - error while cleaning the attached database");
	//	sqlite3_result_error(context, pzErrMsg, -1);
	//	sqlite3DbFree(db, pzErrMsg);
	//	return;
	//}

	// Save the current value of the database flags so that it can be
	// restored before returning. Then set the writable-schema flag, and
	// disable CHECK and foreign key constraints.
	saved_flags = db->flags;
	saved_nChange = db->nChange;
	saved_nTotalChange = db->nTotalChange;
	saved_mTrace = db->mTrace;
	db->flags |= (SQLITE_WriteSchema | SQLITE_IgnoreChecks
		          | SQLITE_PreferBuiltin | SQLITE_Vacuum);
	db->flags &= ~(SQLITE_ForeignKeys | SQLITE_ReverseOrder | SQLITE_CountRows);
	db->mTrace = 0;

	sqlite3BtreeSetCacheSize(pTo, db->aDb[nFrom].pSchema->cache_size);
	sqlite3BtreeSetSpillSize(pTo, sqlite3BtreeSetSpillSize(pFrom,0));
	sqlite3BtreeSetPagerFlags(pTo, PAGER_SYNCHRONOUS_OFF|PAGER_CACHESPILL);


	// Query the schema of the main database. Create a mirror schema
	// in the temporary database.
	db->init.iDb = nTo; /* force new CREATE statements into toDb */
	rc = sqlcodec_execSqlF(db, &pzErrMsg,
		"SELECT sql FROM \"%w\".sqlite_master"
		" WHERE type='table' AND name<>'sqlite_sequence'"
		" AND coalesce(rootpage,1)>0",
		fromDb
	);
	if( rc!=SQLITE_OK ) goto end_of_export;
	rc = sqlcodec_execSqlF(db, &pzErrMsg,
		"SELECT sql FROM \"%w\".sqlite_master"
		" WHERE type='index' AND length(sql)>10",
		fromDb
	);
	if( rc!=SQLITE_OK ) goto end_of_export;
	db->init.iDb = 0;

	// Loop through the tables in the main database. For each, do
	// an "INSERT INTO vacuum_db.xxx SELECT * FROM main.xxx;" to copy
	// the contents to the temporary database.
	rc = sqlcodec_execSqlF(db, &pzErrMsg,
		"SELECT 'INSERT INTO \"%w\".'||quote(name)"
		"||' SELECT * FROM \"%w\".'||quote(name)"
		"FROM \"%w\".sqlite_master "
		"WHERE type='table' AND coalesce(rootpage,1)>0",
		toDb, fromDb, toDb
	);
	assert( (db->flags & SQLITE_Vacuum)!=0 );
	db->flags &= ~SQLITE_Vacuum;
	if( rc!=SQLITE_OK ) goto end_of_export;

	// Copy the triggers, views, and virtual tables from the main database
	// over to the temporary database.  None of these objects has any
	// associated storage, so all we have to do is copy their entries
	// from the SQLITE_MASTER table.
	rc = sqlcodec_execSqlF(db, &pzErrMsg,
		"INSERT INTO \"%w\".sqlite_master"
		" SELECT * FROM \"%w\".sqlite_master"
		" WHERE type IN('view','trigger')"
		" OR(type='table' AND rootpage=0)",
		toDb, fromDb
	);

end_of_export:
	db->init.iDb = 0;
	db->flags = saved_flags;
	db->nChange = saved_nChange;
	db->nTotalChange = saved_nTotalChange;
	db->mTrace = saved_mTrace;

	if (rc)
	{
		if (pzErrMsg != NULL)
		{
			sqlite3_result_error(context, pzErrMsg, -1);
			sqlite3DbFree(db, pzErrMsg);
		}
		else
		{
			sqlite3_result_error(context, sqlite3ErrStr(rc), -1);
		}
	}
}
/*
* Implementation of an "key" function that allows set new key to database
* without re-encryption, usually right after opening the database.
*     SELECT key(x, y);
*  x - database name,
*  y - database key.
* It's the same as PRAGMA key.
* SELECT key('dbname','');         //drop codec and key if it was installed
* SELECT key('dbname','password'); //set new key by passphrase
* SELECT key('dbname','ABC...Z='); //set new key by base64 prekey
*/
void sqlcodec_key_function(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	int rc = SQLITE_OK;     /* Return code from service routines */
	char *pzErrMsg = NULL;
	char *dbName;int nTo;
	void *pKey=NULL;int nKey=0;

	sqlite3 *db = sqlite3_context_db_handle(context);

	if (!db->autoCommit) {
		sqlite3SetString(&pzErrMsg, db, "cannot key from within a transaction");
		sqlite3_result_error(context, pzErrMsg, -1);
		sqlite3DbFree(db, pzErrMsg);
		return;
	}
	if (db->nVdbeActive > 1) {
		sqlite3SetString(&pzErrMsg, db, "cannot key - SQL statements in progress");
		sqlite3_result_error(context, pzErrMsg, -1);
		sqlite3DbFree(db, pzErrMsg);
		return;
	}

	dbName = (char*)sqlite3_value_text(argv[0]);
	pKey = (void*)sqlite3_value_text(argv[1]);
	nKey = sqlite3_value_bytes(argv[1]);
	nTo = sqlite3FindDbName(db, dbName);

	if (nTo<0 || nKey<0) {
		sqlite3SetString(&pzErrMsg, db, "cannot key - database error");
		sqlite3_result_error(context, pzErrMsg, -1);
		sqlite3DbFree(db, pzErrMsg);
		return;
	}

	rc = sqlite3_key_v2(db, dbName, pKey, nKey);
	if(rc != SQLITE_OK)
		sqlite3_result_error(context, sqlite3ErrStr(rc), -1);
}
/*
* Implementation of an "rekey" function that allows set new key to database
* with full re-encryption.
*     SELECT rekey(x, y);
*  x - database name,
*  y - database key.
* It's the same as PRAGMA rekey.
* SELECT rekey('dbname','');         //unencrypt if it was installed
* SELECT rekey('dbname','password'); //re-encrypt by passphrase
* SELECT rekey('dbname','ABC...Z='); //re-encrypt by base64 prekey
*/
void sqlcodec_rekey_function(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	int rc = SQLITE_OK;     /* Return code from service routines */
	char *pzErrMsg = NULL;
	char *dbName;int nTo;
	void *pKey=NULL;int nKey=0;

	sqlite3 *db = sqlite3_context_db_handle(context);

	if (!db->autoCommit) {
		sqlite3SetString(&pzErrMsg, db, "cannot rekey from within a transaction");
		sqlite3_result_error(context, pzErrMsg, -1);
		sqlite3DbFree(db, pzErrMsg);
		return;
	}
	if (db->nVdbeActive > 1) {
		sqlite3SetString(&pzErrMsg, db, "cannot rekey - SQL statements in progress");
		sqlite3_result_error(context, pzErrMsg, -1);
		sqlite3DbFree(db, pzErrMsg);
		return;
	}

	dbName = (char*)sqlite3_value_text(argv[0]);
	pKey = (void*)sqlite3_value_text(argv[1]);
	nKey = sqlite3_value_bytes(argv[1]);
	nTo = sqlite3FindDbName(db, dbName);

	if (nTo<0 || nKey<0) {
		sqlite3SetString(&pzErrMsg, db, "cannot rekey - database error");
		sqlite3_result_error(context, pzErrMsg, -1);
		sqlite3DbFree(db, pzErrMsg);
		return;
	}

	rc = sqlite3_rekey_v2(db, dbName, pKey, nKey);
	if(rc != SQLITE_OK)
		sqlite3_result_error(context, sqlite3ErrStr(rc), -1);
}
/*
* Implementation of an "attach" function.
*     SELECT attach(x, y, z);
*  x - database file name,
*  y - database name,
*  z - database key.
* It's the same as ATTACH DATABASE x AS y KEY z.
* SELECT attach('file','dbname','');         //without key
* SELECT attach('file','dbname','password'); //with passphrase
* SELECT attach('file','dbname','ABC...Z='); //with base64 prekey
*/
void sqlcodec_attach_function(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	int rc = SQLITE_OK;     /* Return code from service routines */
	char *pzErrMsg = NULL;
	char *dbFile,*dbName;
	void *pKey=NULL;int nKey=0;

	sqlite3 *db = sqlite3_context_db_handle(context);

	if (!db->autoCommit) {
		sqlite3SetString(&pzErrMsg, db, "cannot attach from within a transaction");
		sqlite3_result_error(context, pzErrMsg, -1);
		sqlite3DbFree(db, pzErrMsg);
		return;
	}
	if (db->nVdbeActive > 1) {
		sqlite3SetString(&pzErrMsg, db, "cannot attach - SQL statements in progress");
		sqlite3_result_error(context, pzErrMsg, -1);
		sqlite3DbFree(db, pzErrMsg);
		return;
	}

	dbFile = (char*)sqlite3_value_text(argv[0]);
	dbName = (char*)sqlite3_value_text(argv[1]);
	pKey = (void*)sqlite3_value_text(argv[2]);
	nKey = sqlite3_value_bytes(argv[2]);

	if (nKey<0) {
		sqlite3SetString(&pzErrMsg, db, "cannot attach - database error");
		sqlite3_result_error(context, pzErrMsg, -1);
		sqlite3DbFree(db, pzErrMsg);
		return;
	}

	rc = sqlcodec_execSqlF(db, &pzErrMsg,
		"ATTACH DATABASE \"%w\" AS \"%w\" KEY \"%w\" ",
		dbFile, dbName, pKey
	);

	if(rc != SQLITE_OK)
		sqlite3_result_error(context, sqlite3ErrStr(rc), -1);
}
/*
* Implementation of an "detach" function.
*     SELECT detach(x);
*  x - database name.
* It's the same as DETACH DATABASE x.
*/
void sqlcodec_detach_function(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	int rc = SQLITE_OK;     /* Return code from service routines */
	char *pzErrMsg = NULL;
	char *dbName;

	sqlite3 *db = sqlite3_context_db_handle(context);

	if (!db->autoCommit) {
		sqlite3SetString(&pzErrMsg, db, "cannot detach from within a transaction");
		sqlite3_result_error(context, pzErrMsg, -1);
		sqlite3DbFree(db, pzErrMsg);
		return;
	}
	if (db->nVdbeActive > 1) {
		sqlite3SetString(&pzErrMsg, db, "cannot detach - SQL statements in progress");
		sqlite3_result_error(context, pzErrMsg, -1);
		sqlite3DbFree(db, pzErrMsg);
		return;
	}

	dbName = (char*)sqlite3_value_text(argv[0]);

	rc = sqlcodec_execSqlF(db, &pzErrMsg,
		"DETACH DATABASE \"%w\" ",
		dbName
	);

	if(rc != SQLITE_OK)
		sqlite3_result_error(context, sqlite3ErrStr(rc), -1);
}








//Call this function after open database to register user functions
SQLITE_API int SQLITE_STDCALL sqlite3codec_register_user_functions(sqlite3 *db)
{
	int rc = SQLITE_ERROR;
	if (db)
	{
		rc  = 0;
		rc |= sqlite3_create_function(db, "export", 2, SQLITE_UTF8, NULL, &sqlcodec_export_function, NULL, NULL);
		rc |= sqlite3_create_function(db, "key",    2, SQLITE_UTF8, NULL, &sqlcodec_key_function, NULL, NULL);
		rc |= sqlite3_create_function(db, "rekey",  2, SQLITE_UTF8, NULL, &sqlcodec_rekey_function, NULL, NULL);
		rc |= sqlite3_create_function(db, "attach",  3, SQLITE_UTF8, NULL, &sqlcodec_attach_function, NULL, NULL);
		rc |= sqlite3_create_function(db, "detach",  1, SQLITE_UTF8, NULL, &sqlcodec_detach_function, NULL, NULL);
	}
	return rc;
}






#ifdef OMIT_CODEC_DEPRECATED
//Additional function 
//SQLITE_API int SQLITE_STDCALL strlen1(char* s, int buflen) { return strlen(s); }
//SQLITE_API int SQLITE_STDCALL memcpy1(byte* pDst, rsize_t pDstSize, byte* pSrc, rsize_t _MaxCount) { return memcpy_s(pDst,pDstSize,pSrc,_MaxCount); }
#endif //OMIT_CODEC_DEPRECATED


#endif //SQLITE_HAS_CODEC
