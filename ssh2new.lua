-- ssh2new.lua (c) 2010, 2017 by Lucio Andrés Illanes Albornoz <lucio@lucioillanes.de>
-- ssh2new.lua
--		A non-comprehensive RFC 425{2,3}-compliant client implementation
-- 	of the Secure Shell (SSH) protocol version 2 for use with Nmap as an NSE
-- 	script superseding the stock `ssh2.lua' script as distributed with at
-- 	least Nmap v5.00, additionally implementing generic authentication
-- 	support and the functionality required to be afforded to it.
--
-- 		Consult the documentation as present in and produced from the
-- 	below NSE fields for further information.
--
-- Licensed under the terms of the MIT license.  Refer to either `LICENSE' as
-- distributed alongside this file or[1] if unavailable. 
--
--	[1] <http://www.opensource.org/licenses/mit-license.php>
--
--{{{ NSE fields
--@version 1.0
--@author Lucio Andrés Illanes Albornoz --<lucio@lucioillanes.de>
--@license MIT
--
--{{{ Description
--[[
Tested with the <code>pkgsrc Nmap v5.35DC1</code> on <code>NetBSD/i386 v5.1</code>.
Requires the accompanying set of diffs to have been applied to Nmap v5.00+.
Originally based on the stock <code>Nmap v5.35DC1 ssh2.lua</code> script.

A non-exhaustive list of things explicitely not supported by this script:
 * The legacy SSH{,1} protocol or any mode compatible with it
 * Reasonably secure Diffie-Hellman key exchanging
 * Mandatory Key Re-Exchange as per RFC 4253 Section 9
 * non-CBC block cipher modes (including CTR and SDCTR)
 * Mitigation of the CBC plaintext recovery side-channel attack described in VU#958563
 * RFC 4254 Channels, Interactive Sessions, X11, and TCP/IP Forwarding
 * The RFC 4252 Host-Based and Public Key authentication methods
 * Kerberos and GSSAPI authentication

Relevant documents and specifications:
 * RFC 2409 -- The Internet Key Exchange (IKE)
 * RFC 2631 -- Diffie-Hellman Key Agreement Method
 * RFC 3629 -- UTF-8, a transformation format of ISO 10646
 * RFC 4250 -- The Secure Shell (SSH) Protocol Assigned Numbers
 * RFC 4251 -- The Secure Shell (SSH) Protocol Architecture
 * RFC 4252 -- The Secure Shell (SSH) Authentication Protocol
 * RFC 4253 -- The Secure Shell (SSH) Transport Layer Protocol
 * RFC 4256 -- Generic Message Exchange Authentication for the Secure Shell Protocol (SSH)
 * RFC 4344 -- SSH Transport Layer Encryption Modes
 * RFC 4345 -- Improved Arcfour Modes for SSH
 * RFC 4419 -- Diffie-Hellman Group Exchange for the Secure Shell (SSH) Transport Layer Protocol
 * draft-ietf-ipsec-ciph-cast128-cbc-00.txt -- The ESP CAST128-CBC Algorithm
 * OpenSSH Security Advisory: cbc.adv -- <http://www.openssh.com/txt/cbc.adv>
 * CPNI Vulnerability Advisory SSH -- <http://www.cpni.gov.uk/Docs/Vulnerability_Advisory_SSH.txt>
 * PuTTY wish ssh2-cbc-weakness -- <http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/ssh2-cbc-weakness.html>

Alternative SSH{,2} brute scanners and related libraries:
 * THC-Hydra -- <http://freeworld.thc.org/thc-hydra/>
 * Ncrack -- <http://sock-raw.org/papers/openssh_library>
 * metasploit -- <http://www.metasploit.com/modules/auxiliary/scanner/ssh/ssh_login>
 * paramiko: SSH2 protocol for python -- <http://www.lag.net/paramiko/>
 * Net::SSH software suite -- <http://net-ssh.rubyforge.org/>
 * Greg Sabino Mullane / Net-SSH-Perl -- <http://search.cpan.org/dist/Net-SSH-Perl/>
 * libssh -- <http://www.libssh.org/>
 * libssh2 -- <http://www.libssh2.org/>
 * sshscan, sshteam, 55hb, pscan{,2}, hscan, [ ... ]

SSH{,2} brute force mitigation monitors:
 * Sshguard -- <http://www.sshguard.net/>
 * sshd_sentry -- <http://linuxmafia.com/pub/linux/security/sshd_sentry/>
 * sshdfilter -- <http://www.csc.liv.ac.uk/~greg/sshdfilter/>
 * ipt_recent -- <http://www.snowman.net/projects/ipt_recent/>
 * BlockHosts -- <http://www.aczoom.com/cms/blockhosts>
 * DenyHosts -- <http://denyhosts.sourceforge.net/>
 * BlockSSHD -- <http://blocksshd.sourceforge.net/>
 * Ssh-faker -- <http://www.pkts.ca/ssh-faker.shtml>
 * Shellter -- <http://shellter.sourceforge.net/>
 * sshutout -- <http://www.techfinesse.com/sshutout/sshutout.html>
 * Fail2ban -- <http://www.fail2ban.org/>
 * pam-abl -- <http://sourceforge.net/projects/pam-abl/>
 * sshban -- <http://nixbit.com/cat/internet/log-analyzers/sshban/>
 * Tattle -- <http://www.securiteam.com/tools/5JP0520G0Q.html>
 * sshit -- <http://anp.ath.cx/sshit/>
--]]
--}}} 
--}}}
--

module(... or "ssh2new",  package.seeall); SSH2 = { };

-- {{{ Public API status tables
-- Last occurred error  = error [format] string constants, severity
Error = {
	["none"]	= { "(No error)", },
	["receive"]	= { "socket:receive(): %s", },
	["receive_buf"]	= { "socket:receive_buf(): %s", },
	["send"]	= { "socket:send(): %s", },

	["disconnect"]	= { "Disconnected: [%d] `%s'; terminated SSH session.", },
	["digest"]	= { "openssl.digest: %s", },
	["ident"]	= { "Remote SSH server does not speak SSH2(?), got: %s", },
	["ident2"]	= { "Invalid identification string `%s' received from remote server.", },
	["algorithm"]	= { "Unable to negotiate an algorithm for /%s/ (offered: `%s';) terminated SSH session.", },
	["kexdh_reply"]	= { "Missing one of K_S, f, or signature in the SSH_MSG_KEXDH_REPLY packet sent by the remote server.", },
	["ctx_init"]	= { "openssl:ctx_init(): %s", },
	["packetlen"]	= { "Packet length %d above 35000.", },
	["mac"]		= { "Corrupted MAC on input.", },
	["gotunimp"]	= { "Received SSH_MSG_UNIMPLEMENTED in response to packet #%d", },
	["expected"]	= { "Unexpected message byte %02X (expected %02X.)", },
	["alreadyconn"]	= { "Already connecting or connected.", },
	["wantservice"]	= { "Expected `%s' SSH_MSG_SERVICE_ACCEPT packet, got `%s' instead.", },
	["notconn"]	= { "Not connected.", },
	["uauthreqd"]	= { "Already requested the `ssh-userauth' service.", },
	["uauthfail"]	= { "Got SSH_MSG_USERAUTH_FAILURE (authentications that may continue: `%s')", },
	["uauthnotreq"]	= { "The `ssh-userauth' service must be requested prior to attempting authentication.", },
	["expected2"]	= { "Unexpected message byte %02X.", },
	["unknown_key"]	= { "Unknown public key type `%s'.", },
	["do_vexchg"]	= { "Tried to re-do version exchange; terminated SSH session.", },
	["do_kexinit"]	= { "Tried to re-do kexinit; terminated SSH session.", },
	["do_kex"]	= { "Tried to re-do key exchange; terminated SSH session.", },
	["do_newkeys"]	= { "Tried to re-do SSH_MSG_NEWKEYS; terminated SSH session.", },
	["notimpl"]	= { "Operation not implemented.", },
	["unknownauth"]	= { "Unknown authentication method `%s'; terminated SSH session.", },
	["wantbytes"]	= { "Expected to receive %d bytes, got %d bytes instead.", },
}

-- SSH connection and authentication status constants
Status = {
	-- Boolean flags
	Connecting		= 0x002,
	Connected		= 0x003,

	-- Connection phase
	DoneVersionExchange	= 0x010,
	DoneKexInit		= 0x020,
	DoneKeyExchange		= 0x030,
	DoneNewKeys		= 0x040,
	RequestedUserAuth	= 0x050,

	-- Authentication status
	AuthFailureContinue	= 0x100,
	AuthFailurePermanent	= 0x200,
	AuthFailure		= 0x300,
}
-- }}}
-- {{{ Public SSH message constants
-- Subset of relevant SSH transport layer and authentication protocol
-- message numbers.
MSG = {
-- [cf. RFC 4253 Section 12 (`Summary of Message Numbers')]
	SSH_MSG_DISCONNECT		= 1,
	SSH_MSG_IGNORE			= 2,
	SSH_MSG_UNIMPLEMENTED		= 3,
	SSH_MSG_DEBUG			= 4,
	SSH_MSG_SERVICE_REQUEST		= 5,
	SSH_MSG_SERVICE_ACCEPT		= 6,
	SSH_MSG_KEXINIT			= 20,
	SSH_MSG_NEWKEYS			= 21,

-- [cf.	RFC 4419 Diffie-Hellman Group Exchange for the Secure Shell (SSH)
--	Transport Layer Protocol]
	SSH_MSG_KEX_DH_GEX_REQUEST_OLD	= 30,
	SSH_MSG_KEX_DH_GEX_GROUP	= 31,
	SSH_MSG_KEX_DH_GEX_INIT		= 32,
	SSH_MSG_KEX_DH_GEX_REPLY	= 33,
	SSH_MSG_KEX_DH_GEX_REQUEST	= 34,

-- [cf. RFC 4253 Section 8 (`Diffie-Hellman Key Exchange')]
	SSH_MSG_KEXDH_INIT		= 30,
	SSH_MSG_KEXDH_REPLY		= 31,

-- [cf. RFC 4252 Section 6 (`Authentication Protocol Message Numbers')]
	SSH_MSG_USERAUTH_REQUEST	= 50,
	SSH_MSG_USERAUTH_FAILURE	= 51,
	SSH_MSG_USERAUTH_SUCCESS	= 52,
	SSH_MSG_USERAUTH_BANNER		= 53,

-- [cf. RFC 4256 Section 5 (`IANA Considerations')]
	SSH_MSG_USERAUTH_INFO_REQUEST	= 60,
	SSH_MSG_USERAUTH_INFO_RESPONSE	= 61,
}
-- }}}

-- {{{ Internal debugging message tables
-- Debugging [format] string and debug level constants
local Debug = {
	["PACKET"]	= { ["lvl"] = 1, ["pfx"] = "from: %-6s enc: %-5s len: %-4d msg: %-2d", },
	["PACKETHEX"]	= { ["lvl"] = 2, ["pfx"] = "from: %-6s enc: %-5s len: %-4d msg: %-2d\n%s", },
	["MSGDBG"]	= { ["lvl"] = 1, ["pfx"] = "msg : %s", },
	["MSGIGN"]	= { ["lvl"] = 2, ["pfx"] = "data: %s", },
	["UNIMPL"]	= { ["lvl"] = 1, ["pfx"] = "seq#: %d", },
	["KEY"]		= { ["lvl"] = 1, ["pfx"] = "char: %c size: %d bytes: %s", },
	["DISCONNECT"]	= { ["lvl"] = 1, ["pfx"] = "msg : %s", },
	["KEX_INIT"]	= { ["lvl"] = 1, ["pfx"] = "type: %-15s keysz: %-3s dgstsz: %-3s blocksz: %-3s discard: %-4s choice: %s", },
	["AUTHSUCC"]	= { ["lvl"] = 1, ["pfx"] = "", },
	["AUTHFAIL"]	= { ["lvl"] = 1, ["pfx"] = "cont: %s", },
	["AUTHNEXT"]	= { ["lvl"] = 1, ["pfx"] = "cont: %s", },
	["BANNER"]	= { ["lvl"] = 1, ["pfx"] = "text: %s", },
	["INFOREQ"]	= { ["lvl"] = 1, ["pfx"] = "name: %s insn: %s prompt[1]: %s", },
	["AUTHPASS"]	= { ["lvl"] = 1, ["pfx"] = "user: %s pass: %s", },
	["AUTHKBD"]	= { ["lvl"] = 1, ["pfx"] = "user: %s pass: %s", },
}
-- }}}
-- {{{ Internal algorithm name translation and parameter table
-- Fixup table matching the qualified names of the various algorithms
-- (including, but not limited to, block ciphers and hash functions) specified
-- by RFC 4253, possibly explicitely specifying key length, mode of operation,
-- and digest size, resp. within the name itself against their corresponding
-- OpenSSL equivalents and {digest, key} {length, size}s.  Additionally includes
-- the key exchange methods specified by RFC 4253 and RFC 4419 as special-case
-- variants, without relying on an OpenSSL implementation of either.
local Algorithms = {
--	 						   RFC-mandated Comment
	-- {{{ [6.3] Encryption [ciphers]
	["3des-cbc"]		= {			-- REQUIRED	three-key 3DES in CBC mode
		["name"]	= "des-ede3-cbc",
		["key_size"]	= 24,
		["block_size"]	= 8,
	},

	["blowfish-cbc"]	= {			-- OPTIONAL	Blowfish in CBC mode
		["name"]	= "bf-cbc",
		["key_size"]	= 16,
		["block_size"]	= 8,
	},

	["aes256-cbc"]		= {
		["name"]	= "aes-256-cbc",	-- OPTIONAL	AES in CBC mode, with a 256-bit key
		["key_size"]	= 32,
		["block_size"]	= 16,
	},

	["aes192-cbc"]		= { 
		["name"]	= "aes-192-cbc",	-- OPTIONAL	AES with a 192-bit key
		["key_size"]	= 24,
		["block_size"]	= 16,
	},

	["aes128-cbc"]  	= {			-- OPTIONAL	AES with a 128-bit key
		["name"]	= "aes-128-cbc",
		["key_size"]	= 16,
		["block_size"]	= 16,
	},

	["arcfour"]		= {			-- OPTIONAL	the ARCFOUR stream cipher with a 128-bit key
		["name"]	= "rc4",
		["key_size"]	= 16,
		["block_size"]	= 8,
	},

	["arcfour128"]		= {			--[RFC 4345 Section 4 (`Algorithm Definitions')
		["name"]	= "rc4",
		["key_size"]	= 16,
		["block_size"]	= 8,
		["discard"]	= 1536,
	},

	["arcfour256"]		= {			--[RFC 4345 Section 4 (`Algorithm Definitions')
		["name"]	= "rc4",
		["key_size"]	= 32,
		["block_size"]	= 8,
		["discard"]	= 1536,
	},

	["cast128-cbc"]		= {			--[The ESP CAST128-CBC Algorithm -- <draft-ietf-ipsec-ciph-cast128-cbc-00.txt>]
		["name"]	= "cast5-cbc",
		["key_size"]	= 16,
		["block_size"]	= 8,
	},
	-- }}}
	-- {{{ [6.4] Data integrity (MAC algorithm digests)
	["hmac-sha1"]    	= {			-- REQUIRED	HMAC-SHA1 (digest length = key length = 20)
		["name"]	= "sha1",
		["digest_size"]	= 20,
		["key_size"]	= 20,
	},

	["hmac-sha1-96"]	= {			-- RECOMMENDED	first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
		["name"]	= "sha1",
		["digest_size"]	= 12,
		["key_size"]	= 20,
	},

	["hmac-md5"]		= {			-- OPTIONAL	HMAC-MD5 (digest length = key length = 16)
		["name"]	= "md5",
		["digest_size"]	= 16,
		["key_size"]	= 16,
	},

	["hmac-md5-96"]		= {			-- OPTIONAL	first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)
		["name"]	= "md5",
		["digest_size"]	= 12,
		["key_size"]	= 16,
	},
	-- }}}
	-- {{{ [6.5] Key Exchange Methods
	["diffie-hellman-group1-sha1"]			-- REQUIRED
				= {
		["name"]	= "diffie-hellman-group1-sha1",
		-- First Oakley Default MODP Group 1024-bit generator
		-- and prime number as specified in RFC 2409 Section 6.1
		-- (ibid) and RFC 4253 Section 8.1 (ibid.)
		["H"]		= "SHA1",
		["g"]		= openssl.bignum_dec2bn("2"),
		["p"]		= openssl.bignum_hex2bn(
	   "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020"
	.. "BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE135"
	.. "6D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5"
	.. "A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"),
	},

	["diffie-hellman-group14-sha1"]			-- REQUIRED
				= {
		["name"]	= "diffie-hellman-group14-sha1",
			-- Oakley MODP Group 14 2048-bit generator and prime
			-- number as specified in RFC 3526 (ibid) and RFC 4253
			-- Section 8.2 (ibid.)
		["H"]		= "SHA1",
		["g"]		= openssl.bignum_dec2bn("2"),
		["p"]		= openssl.bignum_hex2bn(
	   "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020"
	.. "BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE135"
	.. "6D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5"
	.. "A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55"
	.. "D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966"
	.. "D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B"
	.. "2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D22"
	.. "61898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"),
	},

	["diffie-hellman-group-exchange-sha1"]		-- RFC 4419 Section 4.1 
				= {
		["H"]		= "SHA1",
		["name"]	= "diffie-hellman-group-exchange-sha1",
	},

	["diffie-hellman-group-exchange-sha256"]	-- RFC 4419 Section 4.2 
				= {
		["H"]		= "SHA256",
		["name"]	= "diffie-hellman-group-exchange-sha256",
	},
	-- }}}
	-- {{{ [6.6] Public Key Algorithms
	-- [cf. [FIPS-180-2] and [RFC3447] (`RSASSA-PKCS1-v1_5.')]
	["ssh-dss"]		= {			-- REQUIRED	sign	Raw DSS Key
		["name"]	= "DSS1",
		["digest_size"]	= 20,
	},

	["ssh-rsa"]		= {			-- RECOMMENDED	sign	Raw RSA Key
		["name"]	= "RSA-SHA1",
		["digest_size"]	= 20,
	},
	-- }}}
}
-- }}}
-- {{{ Internal SSH server bug constants and identification string pattern table
-- XXX document
local BUG = {
	-- {{{ From compat.c [as of OpenSSH NetBSD_Secure_Shell-20080403]
	SSH_BUG_BIGENDIANAES		=  2,	-- XXX add
	SSH_BUG_DERIVEKEY		=  4,
	SSH_BUG_FIRSTKEX		=  7,
	SSH_BUG_HMAC			=  9,
	SSH_BUG_NOREKEY			= 12,
	SSH_BUG_RSASIGMD5		= 20,	-- XXX add
	SSH_BUG_SIGBLOB			= 22,	-- XXX add
	SSH_OLD_DHGEX			= 24,
	-- }}}
	-- {{{ From SSH.C [as of PuTTY v0.60 (Release)]
	BUG_SSH2_DERIVEKEY		= 30,
	BUG_SSH2_HMAC			= 31,
	BUG_SSH2_REKEY			= 33,	-- XXX add
	BUG_SSH2_RSA_PADDING		= 34,	-- XXX add
	-- }}}
}

-- Do note that the patterns within each table element are Lua patterns as
-- described in[1] and neither regular expressions nor globs.
-- [1] <http://www.lua.org/manual/5.1/manual.html#5.4.1>
local COMPAT = {
	-- {{{ From compat.c [as of OpenSSH NetBSD_Secure_Shell-20080403]
	{
		["patterns"] = {
			"^OpenSSH-2%.0.*", "^OpenSSH-2%.1.*",
			"^OpenSSH_2%.1.*", "^OpenSSH_2%.2.*",
		},

		["bugs"] = { BUG.SSH_OLD_DHGEX, BUG.SSH_BUG_NOREKEY, },
	},

	{
		["patterns"] = { "^OpenSSH_2%.3%.0.*", },
		["bugs"] = {
			BUG.SSH_BUG_BIGENDIANAES, BUG.SSH_OLD_DHGEX,
			BUG.SSH_BUG_NOREKEY,
		},
	},

	{
		["patterns"] = { "^OpenSSH_2%.3%..*", },
		["bugs"] = {
			BUG.SSH_BUG_BIGENDIANAES, BUG.SSH_OLD_DHGEX,
			BUG.SSH_BUG_NOREKEY,
		},
	},

	{
		["patterns"] = {
			"^OpenSSH_2%.5%.0p1.*", "^OpenSSH_2%.5%.1p1.*",
		},

		["bugs"] = {
			BUG.SSH_BUG_BIGENDIANAES, BUG.SSH_OLD_DHGEX,
			BUG.SSH_BUG_NOREKEY,
		},
	},

	{
		["patterns"] = {
			"^OpenSSH_2%.5%.0.*", "^OpenSSH_2%.5%.1.*",
			"^OpenSSH_2%.5%.2.*",
		},

		["bugs"] = {
			BUG.SSH_OLD_DHGEX, BUG.SSH_BUG_NOREKEY,
		},
	},

	{
		["patterns"] = { "^OpenSSH_2%.5%.3.*", },
		["bugs"] = { BUG.SSH_BUG_NOREKEY, },
	},

	{
		["patterns"] = { "^Sun_SSH_1%.0.*", },
		["bugs"] = { BUG.SSH_BUG_NOREKEY, },
	},

	{
		["patterns"] = { "^2%.1%.0.*", },
		["bugs"] = {
			BUG.SSH_BUG_SIGBLOB, BUG.SSH_BUG_HMAC,
			BUG.SSH_BUG_RSASIGMD5, BUG.SSH_BUG_FIRSTKEX,
		},
	},

	{
		["patterns"] = { "^2%.1 .*", },
		["bugs"] = {
			BUG.SSH_BUG_SIGBLOB, BUG.SSH_BUG_HMAC,
			BUG.SSH_BUG_RSASIGMD5, BUG.SSH_BUG_FIRSTKEX,
		},
	},

	{
		["patterns"] = {
			"^2%.0%.13.*", "^2%.0%.14.*", "^2%.0%.15.*",
			"^2%.0%.16.*", "^2%.0%.17.*", "^2%.0%.18.*",
			"^2%.0%.19.*",
		},

		["bugs"] = {
			BUG.SSH_BUG_SIGBLOB, BUG.SSH_BUG_HMAC,
			BUG.SSH_BUG_RSASIGMD5, BUG.SSH_BUG_FIRSTKEX,
		},
	},

	{
		["patterns"] = { "^2%.0%.11.*", "^2%.0%.12.*", },
		["bugs"] = {
			BUG.SSH_BUG_SIGBLOB, BUG.SSH_BUG_HMAC,
			BUG.SSH_BUG_RSASIGMD5, BUG.SSH_BUG_FIRSTKEX,
		},
	},

	{
		["patterns"] = { "^2%.0%..*", },
		["bugs"] = {
			BUG.SSH_BUG_SIGBLOB, BUG.SSH_BUG_HMAC,
			BUG.SSH_BUG_RSASIGMD5, BUG.SSH_BUG_DERIVEKEY,
			BUG.SSH_BUG_FIRSTKEX,
		},
	},

	{
		["patterns"] = { "^2%.2%.0.*", "^2%.3%.0.*", },
		["bugs"] = {
			BUG.SSH_BUG_HMAC, BUG.SSH_BUG_RSASIGMD5,
			BUG.SSH_BUG_FIRSTKEX,
		},
	},

	{
		["patterns"] = { "^2%.3%..*", },
		["bugs"] = { BUG.SSH_BUG_RSASIGMD5, BUG.SSH_BUG_FIRSTKEX, },
	},

	{
		["patterns"] = { "^2%..*", },
		["bugs"] = { BUG.SSH_BUG_FIRSTKEX, },
	},
	-- }}}
	-- {{{ From SSH.C [as of PuTTY v0.60 (Release)]
	{
		["patterns"] = {
			"^.* VShell", "^2%.1%.0.*", "^2%.0%..*",
			"^2%.2%.0.*", "^2%.3%.0.*", "^2%.1 .*",
		},

		["bugs"] = { BUG.BUG_SSH2_HMAC, },
	},

	{
		["patterns"] = { "^.* VShell", "^2%.0%.0.*", "^2%.0%.10.*", },
		["bugs"] = { BUG.BUG_SSH2_DERIVEKEY, },
	},

	{
		["patterns"] = {
			"^OpenSSH_2%.[5-9].*", "^OpenSSH_3%.[0-2].*",
		},

		["bugs"] = { BUG.BUG_SSH2_RSA_PADDING, },
	},

	{
		["patterns"] = {
			"^DigiSSH_2%.0", "^OpenSSH_2%.[0-4].*",
			"^OpenSSH_2%.5%.[0-3].*",
			"^Sun_SSH_1%.0", "^Sun_SSH_1%.0%.1",
			"^WeOnlyDo-.*",
		},

		["bugs"] = { BUG.BUG_SSH2_REKEY, },
    	},
	-- }}}
}
-- }}}

-- {{{ Public error handling and debugging functions
--- Convenience wrapper setting the string describing the last detected and
-- occured error as detected to the file and line whence the latter
-- originated and the supplied error string for a given <code>Session</code>.
--@param error_type An index into the global <code>Error</code> string table identifying its [format] string.
--@param ... The optional arguments to format into the <code>Error</code> [format] string.
--@return The formatted error string.
function SSH2:set_last_error(error_type, ...)
	local status, _
	local error = "(Unknown error)"
	local file = debug.getinfo(2, "S").source
	local line = debug.getinfo(2, "l").currentline
	-- [cf. <http://lua-users.org/wiki/FileLineMacros>]


	if(Error[error_type])
	then	status, _ = pcall(string.format, Error[error_type], unpack(arg))
		if status then error = _ end
	end

	file = string.gsub(file, "(.*/)(.*)", "%2") or file
	self.last_error = file .. ":" .. line .. " " .. error
	return self.last_error
end

--- Convenience wrapper allowing for structured debugging output.
--@param dbg_type An index into the global <code>Debug</code> prefix [format] string and level table.
--@param ... The optional arguments to format into the [format] string.
function SSH2:print_debug(dbg_type, ...)
	local file = debug.getinfo(2, "S").source
	local line = debug.getinfo(2, "l").currentline
	-- [cf. <http://lua-users.org/wiki/FileLineMacros>]

	local clock = os.date(self.timestamp_fmt, nmap.clock_ms() / 1000)
	local pfx = Debug[dbg_type]["pfx"]


	assert(Debug[dbg_type])
	file = string.gsub(file, "(.*/)(.*)", "%2") or file
	stdnse.print_debug(
		Debug[dbg_type]["lvl"],
		"%-8s.%04d %-10s:%-5s r:%-3s w:%-3s %-10s" .. pfx,
		clock, nmap.clock_ms() % 1000, file, line,
		tostring(self.seq.r), tostring(self.seq.w),
		dbg_type, unpack(arg))
end

--- Dumps a hexadecimal representation of a raw packet including its
-- corresponding sequence number, and a prefix indicating its direction.
--@param packet Decrypted, not necessarily authenticated, SSH2 packet.
--@param from_server <code>true</code> if <code>packet</code> received from server, <code>false</code> if sent by us.
--@param encrypted <code>true</code> if <code>packet</code> is encrypted, <code>false</code> otherwise
function SSH2:dump_packet(packet, from_server, encrypted)
	local _
	local pfx, seq, msg, packet_hex, dbg_type
	local packet_hex = ""


	if from_server then pfx = "Server" else pfx = "Client" end
	if(not encrypted)
	then	_, _, _, msg = bin.unpack(">Icc", packet)
	else	msg = 0
	end

	if(Debug["PACKETHEX"]["lvl"] <= nmap.debugging())
	then	local offset
		for nbyte=1, packet:len()
		do	offset, _ = bin.unpack("H1", packet, offset)
			packet_hex = (packet_hex or "") .. _ .. " "

			if((nbyte %  8) == 0)
			then	packet_hex = packet_hex ..  " "
			end

			if((nbyte % 16) == 0)
			then	packet_hex = packet_hex .. "\n"
			end
		end

		dbg_type = "PACKETHEX"
	else	dbg_type = "PACKET"
	end

	self:print_debug(
		dbg_type, pfx,
		tostring(encrypted), packet:len(), msg, packet_hex)
end

--- Dumps a hexadecimal representation of an IV or a key.
--@param Kc The IV or the key's identifying character byte.
--@param K The raw IV or key.
--@see <code>RFC 4253 Section 7.2 (`Output from Key Exchange')</code>
function SSH2:dump_key(Kc, K)
	local Klen = K:len()
	local _, K = bin.unpack("H" .. K:len(), K)
	self:print_debug("KEY", Kc:byte(), Klen, K)
end
-- }}}
-- {{{ Public wrapper functions
--- XXX document
function SSH2:TIMEOUT_SET()
	if(self.timeout)
	then	self.last_IO = nmap.clock_ms()
		self.socket:set_timeout(self.timeout)
	end
end

--- XXX document
function SSH2:TIMEOUT_UPD()
	if(self.timeout)
	then	self.timeout =  self.timeout - (nmap.clock_ms() - self.last_IO)
		self.last_IO = nmap.clock_ms()
	end
end

--- Convenience wrapper around the <code>receive_buf</code> NSE function
-- adjusting the corresponding I/O timeout value in accordance both with
-- its current value for the corresponding <code>Session</code> and
-- thereafter, the delta between the former and the time spent blocking
-- for network I/O and receiving data.
--@param nbytes The exact amount of bytes to receive, possibly blocking in the process.
--@return Either <code>true</code> and the received raw <code>packet</code> or <code>false</code> and an <code>error string</code>.
function SSH2:receive_buf(nbytes)
	local packet


	self:TIMEOUT_SET()
	 status, packet = self.socket:receive_buf(match.numbytes(nbytes))
	self:TIMEOUT_UPD()

	if(not status)
	then	return false, self:set_last_error("receive_buf", packet)
	end

	if(nbytes ~= packet:len())
	then	return	false,
			self:set_last_error("wantbytes", nbytes, packet:len())
	else	return	true, packet
	end
end

--- Handles a received <code>SSH_MSG_DISCONNECT</code> packet by printing
-- the <code>reason</code> string and integer accompanying the former given
-- an appropriate debugging level.
--@param payload The packet's <code>payload</code>, including message byte.
--@see <code>RFC 4253 Section 11.1 (`Disconnect Message')</code>
--@return <code>false</code>, allowing for convenient <code>return</code> idioms.
function SSH2:handle_disconnect(payload)
	local reason_code, reason, msg, last_error

	_, _, reason_code, reason, _ = bin.unpack(">cIaa", payload)
	last_error = self:set_last_error("disconnect", reason_code, reason)
	self:print_debug("DISCONNECT", self.last_error);
	self:destroy(); return false, last_error;
end

--- XXX document
function SSH2:destroy()
	self.status = { }; if self.socket then self.socket:close() end;
	self.ctx = { }; self.seq = { }; self.kex = { }; self.kexinit = { };
end
-- }}}
-- {{{ Public {de,en}cryption, integrity, and key derivation functions
--- Computes and truncates the MAC of a decrypted, either received, or to be
-- sent packet, employing the corresponding digest function and length as
-- negotiated during connection establishment, and the sequence number
-- corresponding to the packet's direction.
--@param packet Raw, unencrypted packet.
--@param client_to_server <code>true</code> if the passed <code>packet</code> shall afterwards be sent to the server, <code>false</code> if it was received by the server.
--@see <code>RFC 4253 Section 6.4 (`Data Integrity')</code>
--@return Either <code>true</code> and the computed <code>MAC</code> or <code>false</code> and an <code>error string</code>.
function SSH2:compute_mac(packet, client_to_server)
	local _
	local malg, mlen, seq


	-- Obtain the previously initialised HMAC context, SSH2 mandated digest
	-- size, and current packet sequence number corresponding to the packet
	-- direction as specified by /client_to_server/.
	if(not client_to_server)
	then	malg = "mac_S"; mlen = self.kex[malg]["digest_size"];
		malg = self.ctx[malg]; seq = self.seq.r;
	else	malg = "mac_C"; mlen = self.kex[malg]["digest_size"];
		malg = self.ctx[malg]; seq = self.seq.w;
	end

	-- Compute the MAC of the specified sequence number and raw packet,
	-- returning the possibly truncated bytes from the beginning of the
	-- former given successful computation, or /nil/ otherwise.
	local mac = malg:hmac(bin.pack(">IA", seq, packet))
	_, mac = bin.unpack("A" .. mlen, mac)
	return mac
end

--- Derives, via truncation or concatenation, a single key from the secrets
-- shared by both the <code>server</code> and the <code>client</code>,
-- resulting from earlier <code>key exchange</code> procedures.
--@param key_size The target key's size, as mandated by the correspondingly negotiatioed algorithm and key size.
--@param Kc The key's character byte as per <code>RFC 4253 Section 7.2 (`Output from Key Exchange')</code>.
--@see <code>RFC 4253 Section 7.2 (`Output from Key Exchange')</code>
--@return Either <code>true</code> and the specified amount of bytes from the beginning of the derived key or <code>false</code> and an <code>error string</code>.
function SSH2:derive_key(key_size, Kc)
	local status, _, msg, K, H, key, Hm, _key


	K = self.kexinit["K"]; H = self.kexinit["H"];
	key = self.kexinit["H"]; Kc = Kc:byte();

	-- Derive the initial key by computing the hash of the concatenated
	-- shared secrets, the session key, and the key character byte
	-- as specified, initialising the temporary table of computed
	-- hashes with the former as its first entry.
	Hm = self.kex["kex"]["H"]

	-- [cf.	kex.c:480, 494 from NetBSD_Secure_Shell-20080403
	-- 	regarding SSH_BUG_DERIVEKEY]
	if(not self.bugs[BUG.SSH_BUG_DERIVEKEY])
	then	msg = bin.pack(">AAcA", K, H, Kc, key)	
	else	msg = bin.pack(">AcA", H, Kc, key)	
	end

	status, key = pcall(openssl.digest, Hm, msg)
	if(not status)
	then	return false, set_last_error("digest", key)
	else	_key = { key, }
	end

	-- Extend the key given a specified key size exceeding the output
	-- of the hash function by employing the scheme detailed in [ibid],
	-- appending the resulting hash to the above initialised temporary
	-- table with each iteration.
	while key:len() < key_size
	do	local Kn_new = table.maxn(_key) + 1


		key = ""

		-- Concatenate the shared secrets and every single hash
		-- computed priorly, and calculate the hash of the resulting
		-- sequence.
		-- [cf.	kex.c:480, 494 from NetBSD_Secure_Shell-20080403
		-- 	regarding SSH_BUG_DERIVEKEY]
		if(not self.bugs[BUG.SSH_BUG_DERIVEKEY])
		then	_key[Kn_new] = bin.pack(">AA", K, H)
		else	_key[Kn_new] = bin.pack(">A", H)
		end

		for Kn=1,(Kn_new - 1),1
		do	_key[Kn_new] = bin.pack(">AA", _key[Kn_new], _key[Kn])
		end

		status, _key[Kn_new] = pcall(openssl.digest, Hm, _key[Kn_new])
		if(not status)
		then	return	false,
				self:set_last_error("digest", _key[Kn_new])
		end

		for Kn=1,(Kn_new - 1),1
		do	key = bin.pack(">AA", key, _key[Kn])
		end
	end

	-- Return the specified amount of bytes from the beginning of the
	-- derived key, possibly implicitly truncating.
	_, key = bin.unpack("A" .. key_size, key)
	return true, key
end
-- }}}
-- {{{ Internal wrapper functions
--- XXX document
--@param ip XXX document
--@param port XXX document
--@param timeout XXX document
--@param socket XXX document
--@param timestamp_fmt XXX document
--@return XXX
function new_session(ip, port, timeout, socket, timestamp_fmt)
	local S = setmetatable({}, {__index = SSH2})


	S.status = { }; S.ip = ip; S.port = port;
	S.timeout = timeout; S.t0 = 0; S.socket = socket;
	S.bugs = { }; S.ctx = { };
	if not timestamp_fmt then S.timestamp_fmt = "%H:%M:%S" end

--	RFC 4253 Section 6.4 (`Data Integrity')
	S.seq = { ["r"] = 0, ["w"] = 0, }

--	RFC 4253 Section 7.1 (`Algorithm Negotiation')
--	RFC 4253 Section 7.2 (`Output from Key Exchange')
	S.kex = { }

--	RFC 4253 Section 8 (`Diffie-Hellman Key Exchange')
	S.kexinit = { }

	return true, S
end

--- XXX document
--@param ssh_name XXX document
--@return XXX
function new_algorithm(ssh_name)
	return setmetatable({}, {__index = Algorithms[ssh_name]})
end

--- Extracts the parameters identifying the supplied public key according to the
-- encoding and algorithm indicated by the first SSH2 BPP /string/ contained
-- within it, preceding the actual key data.
--@param public_key The raw <code>public key</code> in format specified in <code>RFC 4253</code>.
--@see <code>RFC 4253 Section 6.6 (`Public Key Algorithms')</code>
--@return Either <code>true</code>, the <code>public key format identifier</code> (e.g. <code>ssh-rsa</code>,) the amount of bits in the <code>public key's public exponent</code>, and the key's actual parameters, or <code>false</code> and an <code>error string</code>.
local extract_public_key = function(public_key)
	local key_type, bits; key = { };


	_, key_type = bin.unpack(">a", public_key)

	if("ssh-dss" == key_type)
	then	_, _, key["p"], key["q"], key["g"], key["y"]
			 = bin.unpack(">aaaaa", public_key)
		bits = openssl.bignum_bin2bn(p):num_bits()
	elseif("ssh-rsa" == key_type)
	then	_, _, key["e"], key["n"]
			= bin.unpack(">aaa", public_key)
		bits = openssl.bignum_bin2bn(n):num_bits()
	else	return false, S:set_last_error("unknown_key", key_type)
	end

	for f, _ in pairs(key) do key[f] = openssl.bignum_mpi2bn(key[f]) end
	return true, key_type, bits, key
end

--- XXX document
--@param msg XXX document
--@see <code>RFC 4251 Section 9.2 (`Control Character Filtering')</code>
--@return XXX document
local function sanitise(msg)
	return msg:gsub("[\r\n]", "")
end
-- }}}

-- {{{ [4.2] Version exchange and compatibility mode determination
--- Performs the <code>Protocol Version Exchange</code> with the remote SSH
-- server, possibly enabling compatibility modes given known bugs present in
-- the remote SSH implementation in accordance with the former's
-- <code>identification string</code>.
--@param ident_C The <code>identification string</code> excluding any terminating <code>CR LF</code> characters to send to the remote server.
--@see <code>RFC 4253 Section 4.2 (`Protocol Version Exchange')</code>
--@return Either <code>true</code> or <code>false</code> and an <code>error string</code>.
function SSH2:do_version_exchange(ident_C)
	local status, ident_S


	-- Ensure that the current Session is in the correct connection phase.
	if(not ((self.status[Status.Connecting])
	and     (not self.status[Status.DoneVersionExchange])))
	then	self:destroy()
		return false, self:set_last_error("do_vexchg")
	end

	repeat
		self:TIMEOUT_SET()
		 status, ident_S = self.socket:receive()
		self:TIMEOUT_UPD()

		if(not status)
		then	self:destroy()
			return false, self:set_last_error("receive", ident_S)
		end

		-- `The server MAY send other lines of data before sending the
		--  version string.  Each line SHOULD be terminated by a
		--  Carriage Return and Line Feed.  Such lines MUST NOT begin
		--  with "SSH-", [ ... ]'
 		if(string.find(ident_S, "SSH-", 1, true))
 		then
 			-- Ignore non-SSH2 speaking SSH(?) daemons; send our
 			-- client identification string given a protocol
			-- version of either 2.0 or 1.99, with the latter
			-- being equivalent to the former given legacy SSH
			-- compatibility [cf. RFC 4253 Section 5.1].
 			if( (nil == string.find(ident_S, "2.0", 5, true))
			and (nil == string.find(ident_S, "1.99", 5, true)))
			then	self:destroy()
 				return	false,
					self:set_last_error("ident", ident_S)
			else	status,
				self.last_error
					= self.socket:send(ident_C .. "\r\n")

				if(not status)
				then	self:destroy()
					return	false,
						self:set_last_error(
							"send", self.last_error)
				end
			end

			-- Store both identification strings bar their
			-- optionally terminating CR-LF pairs in the
			-- session table, since they are required in later
			-- stages of the SSH2 connection setup.
			self.kexinit["V_C"] = ident_C
			self.kexinit["V_S"] = ident_S:gsub("[\r\n]", "")

			-- Determine whether to and do, if applying, enable the
			-- compatibility mode{,s} corresponding to the remote
			-- SSH implementation as identified by its
			-- identification string by iteratively toggling each
			-- known bug given an implementation matching the
			-- corresponding pattern.
			--	Do note that Lua's lack of binary operators
			-- and enumerations makes this, as usual, ludicrous to
			-- accomplish.
			local version_S = ident_S:match(
				"^SSH%-%d+%.%d+%-([^\n]+)")
			if(not version_S)
			then	self:destroy()
				return	false,
					self:set_last_error("ident2", ident_S)
			end

			for _, Tp in pairs(COMPAT)
			do	for _, pattern in pairs(Tp["patterns"])
				do	if(version_S:match(pattern))
					then	for _, bug in pairs(Tp["bugs"])
						do	self.bugs[bug] = true
						end
					end
				end
			end
	
			self.status[Status.DoneVersionExchange] = true
			return true
 		end
	until false
end
-- }}}
-- {{{ [4.2] Key exchange algorithm negotiation
--- Initiate the key exchange by and do negotiate the algorithms aswell as their
-- parameters to employ immediately after the former procedure has successfully
-- finished, attempting to coalesce the remote SSH server's offers with the
-- corresponding equivalents as supported by this script itself, the underlying
-- OpenSSL implementation on the host system, and, optionally, the choice
-- preferred by the caller.
--	Do note that the `none' cipher and MAC algorithm when offered by
-- the server are not supported.
--@param preferred_algorithm An optionally specified table indicating one single algorithm per category that should, if possible, be preferred during algorithm negotiation, with the according categories being: <code>encryption_C</code>, <code>encryption_S</code>, <code>mac_C</code>, and <code>mac_S</code>.
--@see <code>RFC 4253 Section 4.2 (`Protocol Version Exchange')</code>
--@return Either <code>true</code> or <code>false</code> and an <code>error string</code>.
function SSH2:do_kex_init(preferred_algorithm)
	local status, _
	local kexinit_S, kexinit_C, offset_S, first_kex_packet_follows


	-- Ensure that the current Session is in the correct connection phase.
	if(not ((self.status[Status.Connecting])
	and     (not self.status[Status.DoneKexInit])))
	then	self:destroy()
		return false, self:set_last_error("do_kexinit")
	end

	-- Expect a SSH_MSG_KEXINIT packet containing the server's supported
	-- offering of algorithms, authenticated later by the latter, thus
	-- requiring retention of the entire packet.  Prepare a corresponding
	-- packet to send in return.
	-- [cf. Section 8 (`Diffie-Hellman Key Exchange.')]
	status, kexinit_S = self:recv_packet(MSG.SSH_MSG_KEXINIT)
	if(not status)
	then	self:destroy()
		return status, kexinit_S
	else	self.kexinit["I_S"] = kexinit_S
		offset_S = 18		-- Skip SSH_MSG_KEXINIT and cookie
		kexinit_C = bin.pack(	-- Prepend SSH_MSG_KEXINIT and cookie
				">cA", MSG.SSH_MSG_KEXINIT,
				openssl.rand_bytes(16))
	end

	-- Discard an optionally following guessed key exchange packet.
	_, _, _, _, _, _, _, _, _, _, _, first_kex_packet_follows
		= bin.unpack(">aaaaaaaaaac", kexinit_S, offset_S)

	-- [cf.	kex.c:451 from NetBSD_Secure_Shell-20080403
	-- 	regarding SSH_BUG_FIRSTKEX]
	if  ((true == first_kex_packet_follows)
	and  (not self.bugs[BUG.SSH_BUG_FIRSTKEX]))
	then	status, _ = self:recv_packet()
		if(not status)
		then	self:destroy()
			return false, _
		end
	end

	-- Iteratively populate the session table's {cipher, digest} table
	-- with references into the corresponding fix-up table to the first
	-- eligible algorithm in each category as offered by the remote SSH
	-- server, augmented with the optionally specified table of preferences.
	for _, category in pairs({
		"kex", "server_host_key",
		"encryption_C", "encryption_S", "mac_C", "mac_S", })
	do	local algorithms_S, algorithm_C

		-- Process each offered algorithm in the comma-separated
		-- /name-list/ for the current category, instantiating a table
		-- for each eligible algorithm present in the global Algorithms
		-- fix-up table.
		-- 	Do also append the latter choice to the SSH_MSG_KEXINIT
		-- packet to send back to the server.
 		offset_S, algorithms_S = bin.unpack(">a", kexinit_S, offset_S)
		if ( preferred_algorithm
		and (preferred_algorithm[category])
		and (algorithms_S:find(preferred_algorithm[category], 1, true)))
		then	algorithms_S
				= preferred_algorithm[category]
				.. "," .. algorithms_S
		end

 		for alg in algorithms_S:gmatch('([^,]+),?')
 		do	if(Algorithms[alg])
 			then	algorithm_C = new_algorithm(alg)
		 		kexinit_C = bin.pack(">Aa", kexinit_C, alg)
				self:print_debug(
					"KEX_INIT", category,
					tostring(algorithm_C["key_size"]),
					tostring(algorithm_C["digest_size"]),
					tostring(algorithm_C["block_size"]),
					tostring(algorithm_C["discard"]), alg)
 				break
			end
 		end

		-- Store the earlier obtained reference in the Session table's
		-- algorithm table under the key named by the current category;
		-- return failure given that none of the offered algorithms were
		-- found to be eligible.
		if(not algorithm_C)
		then	self:destroy()
			return	false,
				self:set_last_error(
					"algorithm", category, algorithms_S)
		else	self.kex[category] = algorithm_C

			-- [cf.	kex.c:281 from NetBSD_Secure_Shell-20080403
			-- 	regarding SSH_BUG_HMAC]
			if  ((category:match("^mac_"))
			and  (self.bugs[BUG.SSH_BUG_HMAC]))
			then	self.kex[category]["key_size"] = 16
			end
		end
	end

	-- Append the remaining, unused fields to the SSH_MSG_KEXINIT packet,
	-- and send to the remote SSH server.
	self.kexinit["I_C"]
		= bin.pack(">AaaaacI", kexinit_C, "none", "none", "", "", 0, 0)

	status, error = self:send_packet(self.kexinit["I_C"])
	if(not status)
	then	self:destroy()
		return false, error
	else	self.status[Status.DoneKexInit] = true
		return true
	end
end
-- }}}
-- {{{ [8]   Diffie-Hellman fixed group and RFC 4419 key exchange
--- Performs the Diffie-Hellman key exchange employing the method negotiated
-- beforehand by exchanging public exponents and deriving the corresponding,
-- thusly shared secrets, possibly obtaining <code>p</code> and <code>g</code>
-- from the server given the <code>RFC 4419</code> non-static group method.
-- Implicitly obtains the remote server's claimed <code>host key</code> without
-- subjecting either of the two to any authentication mechanisms, leaving
-- confirmation of the claimed identity (and therefore, security of the entire
-- transport in a wider sense) to the caller.
--
-- 	Do note that verification of the <code>signature</code> as sent by the
-- remote SSH server, generated by the <code>private key</code> corresponding
-- to the <code>public host key</code> also sent by the former must, if
-- necessary or desired, be separately requested by the caller by calling the
-- <code>verify_signature</code> function.
--
--	Do also note that this particular implementation of the Diffie-Hellman
-- key exchange is unlikely to be secure, in particular due to relying on a
-- predictable PRNG aswell as not subjecting any of the involved values to
-- stringent constraints as either implied or mandated by the various RFC,
-- drafts, analysis, and other such material.
--@see <code>RFC 4253 Section 8 (`Diffie-Hellman Key Exchange')</code> and <code>RFC 4419 -- Diffie-Hellman Group Exchange for the Secure Shell (SSH) Transport Layer Protocol</code>
--@return Either <code>true</code> or <code>false</code> and an <code>error string</code>.
function SSH2:do_key_exchange()
	local status, error, _
	local need, kexdh, p, g, x, e, f
	local msg = { }
	local H = ""


	-- Ensure that the current Session is in the correct connection phase.
	if(not ((self.status[Status.Connecting])
	and     (not self.status[Status.DoneKeyExchange])))
	then	self:destroy()
		return false, self:set_last_error("do_kex")
	end

	-- Estimate the amount of bits and entropy needed from the Diffie-
	-- Hellman key exchange output from the employed ciphers' and MAC
	-- algorithm's key lengths, block sizes, and digest sizes, resp.,
	-- not truncating the result to the employed hash function's digest
	-- size.
	-- [cf.	SSH.C:5563, SSHDH.C:158 from PuTTY 0.60;
	--	kex.c:593 from OpenSSH NetBSD_Secure_Shell-20080403]
	need = 0
	for _, category in pairs({
			"encryption_C", "encryption_S", "mac_C", "mac_S", })
	do	for _, field in pairs({
				"key_size", "block_size", "digest_size", })
		do	local n = self.kex[category][field]
			if n and (need < (n * 8)) then need = (n * 8) end
		end
	end

	-- Determine whether to compute the public exponent and its components
	-- from either of the two static groups specified in RFC 4253 Sections
	-- 8.1 and 8.2 (further defined in RFC 2631, X9.42, and others) or to
	-- first obtain p and q from the remote SSH server via the protocol
	-- specified in RFC 4419, generate the former values accordingly, and
	-- send the public exponent to the server. 
	if((not self.kex["kex"]["g"]) or (not self.kex["kex"]["p"]))
	then	-- Scale the preferred size in bits of p in proportion with the
		-- estimated amount of bits in steps of and with a lower minimum
		-- of 512 bits.
		-- [cf.	SSH.C:5563, SSHDH.C:158 from PuTTY 0.60]
		local need_p = 512 * (2 ^ math.floor(need / 64))


		-- Send the constraints the prime number and generator shall
		-- adhere to to to the remote SSH server, and store each
		-- in the Session table since they form part of the
		-- concatenation yielding H, implicitely authenticating them.
		if need_p < 8192 then need_p = 8192 end


		-- [cf.	kexgexc.c:61 from NetBSD_Secure_Shell-20080403
		-- 	regarding SSH_OLD_DHGEX]
		if(self.bugs[BUG.SSH_OLD_DHGEX])
		then	status,
			error = self:send_packet(
					bin.pack(">cI",
					MSG.SSH_MSG_KEX_DH_GEX_REQUEST,
						need_p))
		else	status,
			error = self:send_packet(
					bin.pack(">cIII",
					MSG.SSH_MSG_KEX_DH_GEX_REQUEST,
					1024,	need_p,	8192))
				--	min,	n,	max
		end

		if(not status)
		then	self:destroy()
			return false, error
		else	self.kexinit["min"] = 1024
			self.kexinit["n"] = need_p
			self.kexinit["max"] = 8192
		end

		-- Extract the {p, g} values sent by the server, using them for
		-- the key exchange process.  Do also store both encoded as
		-- /mpint/ in the Session table (see above.)
		status, kexdh = self:recv_packet(MSG.SSH_MSG_KEY_DH_GEX_GROUP)
		if(not status)
		then	self:destroy()
			return false, error
		else	_, _, p, g = bin.unpack(">caa", kexdh)
			p = openssl.bignum_bin2bn(p)
			g = openssl.bignum_bin2bn(g)

			self.kexinit["p"] = p:tompi()
			self.kexinit["g"] = g:tompi()

			msg["init"] = MSG.SSH_MSG_KEX_DH_GEX_INIT
			msg["reply"] = MSG.SSH_MSG_KEX_DH_GEX_REPLY

			msg["H"] = {
				{ "V_C", "a", }, { "V_S", "a", },
				{ "I_C", "a", }, { "I_S", "a", },
				{ "K_S", "a", }, { "min", "I", },
				{ "n",   "I", }, { "max", "I", },
				{ "p",   "A", }, { "g",   "A", },
				{ "e",   "A", }, { "f",   "A", },
				{ "K",   "A", }}

			-- [cf.	kexgexc.c:61 from NetBSD_Secure_Shell-20080403
			-- 	regarding SSH_OLD_DHGEX]
			if(self.bugs[BUG.SSH_OLD_DHGEX])
			then	table.remove(msg["H"], 6)	-- min
				table.remove(msg["H"], 7)	-- max
			end
		end
	else	-- Use the prime number and generator specified by the static
		-- group negotiated earlier.
		p = self.kex["kex"]["p"]; g = self.kex["kex"]["g"];

		msg["init"] = MSG.SSH_MSG_KEXDH_INIT
		msg["reply"] = MSG.SSH_MSG_KEXDH_REPLY
		msg["H"] = {
			{ "V_C", "a", }, { "V_S", "a", },
			{ "I_C", "a", }, { "I_S", "a", },
			{ "K_S", "a", }, { "e",   "A", },
			{ "f",   "A", }, { "K",   "A", }}
	end

	-- Generate a predictable pseudo-random number containing the amount
	-- of bits estimated to be needed earlier to use as private key
	-- (the shared secret number `ZZ' as per X9.42 and RFC 2631,) and send
	-- it to the remote SSH server.
	x = openssl.bignum_pseudo_rand(need)
	self.kexinit["e"] = openssl.bignum_mod_exp(g, x, p)
	self.kexinit["e"] = self.kexinit["e"]:tompi()

	status,
	error = self:send_packet(
			bin.pack(">cA", msg["init"], self.kexinit["e"]))
	if not status then self:destroy(); return status, error; end

	-- Expect the remote SSH server's public host key (and certificates,
	-- if any,) its own computed public DH exponent, and signature of H,
	-- storing all in the Session table to use in server identification and
	-- key derivation.  Do note that verification of the signature as
	-- received is left to be requested by the caller, and not necessitated
	-- here due to the computation cost involved in the process potentially
	-- unnecessary and possibly undesirable.
	status, kexdh = self:recv_packet(msg["reply"])
	if not status then self:destroy(); return status, kexdh end
	_, _, self.kexinit["K_S"], f, self.kexinit["signature"]
		= bin.unpack(">caaa", kexdh)

	-- Validate the received values, derive and store the shared
	-- secret K from x, p, and the remote SSH server's public
	-- exponent.
	if(not (self.kexinit["K_S"] and f and self.kexinit["signature"]))
	then	self:destroy()
		return false, self:set_last_error("kexdh_reply")
	else	f = openssl.bignum_bin2bn(f)
		self.kexinit["f"] = f:tompi()
		self.kexinit["K"] = openssl.bignum_mod_exp(f, x, p)
		self.kexinit["K"] = self.kexinit["K"]:tompi()
	end

	-- Compute H by hashing the concatenation of the values specified for
	-- the key exchange method corresponding to the {sub,}set of values
	-- exchanged up to this point, authenticating them in the process
	-- given that the identify of the remote SSH server as per K_S is
	-- can be absolutely confirmed [cf. Step 3 in RFC 4253 Section 8].
	for _, Ft in pairs(msg["H"])
	do	H = bin.pack(">A" .. Ft[2], H, self.kexinit[Ft[1]])
	end

	status, self.kexinit["H"]
		= pcall(openssl.digest, self.kex["kex"]["H"], H)
	if(not status)
	then	self:destroy()
		return false, self.kexinit["H"]
	else	self.status[Status.DoneKeyExchange] = true
		return true
	end
end
-- }}}
-- {{{ [7.2] Output from Key Exchange
--- Derives the set of shared key material, initialises cipher and digest
-- contexts, and enables use of all negotiated algorithms, subsequently
-- finishing connection setup by establishing a fully encrypted and
-- authenticated SSH2 transport.
--@see <code>RFC 4253 Section 7.2. (`Output from Key Exchange')</code>
--@return Either <code>true</code> or <code>false</code> and an <code>error string</code>.
function SSH2:do_newkeys()
	local status, error


	-- Ensure that the current Session is in the correct connection phase.
	if(not ((self.status[Status.Connecting])
	and     (not self.status[Status.DoneNewKeys])))
	then	self:destroy()
		return false, self:set_last_error("do_newkeys")
	end

	-- Send a SSH_MSG_NEWKEYS packet to the server to indicate that the
	-- encryption and MAC algorithms aswell as the corresponding key
	-- material negotiated and derived earlier may now be used, expecting
	-- an equivalent reply in return.
	status, error = self:send_packet(bin.pack("c", MSG.SSH_MSG_NEWKEYS))
	if(not status)
	then	self:destroy()
		return false, error
	else	status, error = self:recv_packet(MSG.SSH_MSG_NEWKEYS)
		if not status then self:destroy(); return false, error end
	end

	-- Derive the IV and keys to use for {{de, en}cryption} and MAC packet
	-- integrity {verification, computation}, both as a hash from the known,
	-- shared values and the differentiating single character byte as
	-- described in [ibid], employing both to initialise an EVP (3) cipher
	-- context for later use by the {de, en}cryption processes, and enable
	-- all algorithms in accordance with the SSH_MSG_NEWKEYS message sent
	-- above.
	-- [cf. <http://lua-users.org/lists/lua-l/2006-12/msg00444.html>
	--	regarding the looping and branching paradigm employed here.]
	for _, Kt in pairs({
			--  Category	 Dir	Context type	IV,	Key byte
			{  "encryption", "C",	"encrypt",	"A",	"C", },
			{  "encryption", "S",	"decrypt",	"B",	"D", },
			{  "mac",	 "C",	"hmac",		nil,	"E", },
			{  "mac",	 "S",	"hmac",		nil,	"F", }})
	do
	repeat	local An, calg, CS, ctx, keys

		CS = Kt[2]; An = Kt[1] .. "_" .. CS; calg = self.kex[An];
		if not calg then break else calg["use"] = true end;
		ctx = Kt[3]; keys = { };

		for _, Kt in pairs({
				{ "iv", Kt[4], }, { "key", Kt[5], },
				{ nil, nil, }})
		do	local name = Kt[1]; local byte = Kt[2]; local key;

			-- Special-case context initialisation to take place
			-- after the corresponding key derivation has taken
			-- place for the current algorithm.
			if((not name) and (not byte))
			then	status, self.ctx[An]
					= pcall(openssl.ctx_init,
						calg["name"], ctx,
						calg["key_size"], keys["key"],
						calg["block_size"], keys["iv"],
						calg["discard"])

				if(not status)
				then	self:destroy()
					return	false,
						self:set_last_error(
							"ctx_init",
							self.ctx[An])
				end
			elseif(byte)
			then	status,
				key = self:derive_key(calg["key_size"], byte)
				if(not status)
				then	self:destroy()
					return false, self.last_error
				else	self:dump_key(byte, key)
					keys[name] = key;
				end
			end
		end
	until true
	end

	self.status[Status.DoneNewKeys] = true
	return true
end
-- }}}

-- {{{ Public packet {de,}marshalling and {de, en}crypting {reception, sending} primitives
--- Receives, optionally decrypts and verifies the integrity (if use of either
-- operations has been enabled beforehand,) of a packet as sent by the remote
-- SSH server, given the negotiated algorithms, parameters, and derived key
-- material for an established connection, handling
-- <code>SSH_MSG_DISCONNECT</code> and <code>SSH_MSG_IGNORE</code> message as a
-- special case.
--@param want_msg The <code>message byte</code> to expect and solely return, or <code>nil</code> given that no particular message is expected. Unexpected messages are discarded.
--@see <code>RFC 4253 Section 6 (`Binary Packet Protocol')</code>, <code>RFC 4253 Section 6.3 (`Encryption')</code>, <code>RFC 4253 Section 6.4 (`Data Integrity')</code>
--@return Either <code>true</code> and the decrypted, and verified (authenticated,) received packet's payload, or <code>false</code> and an <code>error string</code> given either failure in any steps of the procedure involved in the processes outlined above, or given an unexpected message.
function SSH2:recv_packet(want_msg)
	local _, offset
	local status, error, nbytes, calg, ctx
	local packet, packet_length, padding_length, payload, msg


	-- Ensure that either a partial or a fully established connection
	-- to an SSH server exists.
	if(not ((self.status[Status.Connecting])
	or      (self.status[Status.Connected])))
	then	return false, self:set_last_error("notconn")
	end

	-- Attempt to receive at most either 8 bytes or as much as the current
	-- cipher block size corresponding to the algorithm negotiated for this
	-- direction, given that encryption is enabled, at first, adhering to
	-- RFC 4253 Section 6:
	-- `Implementations SHOULD decrypt the length after receiving the
	--  first 8 (or cipher block size, whichever is larger) bytes of a
	--  packet.'
	nbytes = 8; calg = self.kex["encryption_S"];
	if((calg) and (calg["use"]))
	then	ctx = self.ctx["encryption_S"]
		if((calg["block_size"]) and (8 < calg["block_size"]))
		then	nbytes = calg["block_size"]
		end
	end

	status, packet = self:receive_buf(nbytes)
	if not status then return false, self.last_error end

	-- Tentatively increment the sequence number, and attempt to
	-- decrypt the received packet data if encryption is enabled. 
	if((calg) and (calg["use"]))
	then	status, packet = pcall(openssl.ctx_crypt, ctx, packet)
		if(not status)
		then	return false, self:set_last_error("decrypt", packet)
		end
	end

	-- Extract this packet /packet length/ and /padding length/,
	-- attempting to receive (and decrypt) the thus determined remainder
	-- of the former, if necessary.  Do also discard packets with an
	-- advertised length above 35000, loosely adhering to RFC 4253
	-- Section 6.1 (`Maximum Packet Length':)
	-- `All implementations MUST be able to process packets with an
	--  uncompressed payload length of 32768 bytes or less and a total
	--  packet size of 35000 bytes or less (including 'packet_length',
	--  'padding_length', 'payload', 'random padding', and 'mac').
	--  The maximum of 35000 bytes is an arbitrarily chosen value
	--  that is larger than the uncompressed length noted above.
	--  Implementations SHOULD support longer packets, where
	--  they might be needed. [ ... ]'
	offset, packet_length, padding_length = bin.unpack(">Ic", packet)
	if(35000 < packet_length)
	then	return false, self:set_last_error("packetlen", packet_length)
	elseif(packet:len() < (packet_length + 4))
	then	status, _ = self:receive_buf(4 + packet_length - packet:len())
		if not status then return false, self.last_error end

		if((calg) and (calg["use"]))
		then	status, _ = pcall(openssl.ctx_crypt, ctx, _)
			if(not status)
			then	return false, self:set_last_error("decrypt", _)
			end
		end

		-- Append the received, and possibly decrypted, data to the
		-- end of the current packet buffer.
		packet = bin.pack("AA", packet, _)
	end

	-- Compute the MAC of the received packet, decrypted if encryption is
	-- enabled, and compare it against the corresponding MAC sent by the
	-- remote SSH server as part of the packet, given that data integrity
	-- is enabled.
	local malg = self.kex["mac_S"]
	if((malg) and (malg["use"]))
	then	local mac_S

		-- Attempt to receive the MAC bytes pertaining to this packet.
		status, mac_S = self:receive_buf(malg["digest_size"])
		if(not status)
		then	return false, self.last_error
		elseif(mac_S ~= self:compute_mac(packet))
		then	return false, self:set_last_error("mac")
		end
	end

	-- Dump the decrypted packet given an appropriate debugging level.
	self:dump_packet(packet, true, false)

	-- Extract the packet's payload, comparing its message byte against the
	-- equivalent as specified by the caller, if applying, returning the
	-- former solely if either any packet was specified to be received
	-- or if a match was made, special-casing SSH_MSG_DISCONNECT,
	-- SSH_MSG_DEBUG, and SSH_MSG_IGNORE messages.
	offset, payload
		= bin.unpack(
			">A" .. packet_length - padding_length - 1,
			packet, offset)

	-- Increment the packet sequence number for this direction.
	self.seq.r = self.seq.r + 1

	_, msg = bin.unpack("c", payload)
	if(msg == MSG.SSH_MSG_DISCONNECT)
	then	-- [cf. RFC 4253 Section 11.1 (`Disconnection Message')]
		return self:handle_disconnect(payload)
	elseif(msg == MSG.SSH_MSG_DEBUG)
	then	-- [cf. RFC 4253 Section 11.3 (`Debug Message')]
		local msg

		_, _, _, msg = bin.unpack(">cca", payload)
		msg = sanitise(msg); self:print_debug("MSGDBG", msg);
		return self:recv_packet(want_msg)
	elseif(msg == MSG.SSH_MSG_IGNORE)
	then	-- [cf. RFC 4253 Section 11.2 (`Ignored Data Message')]
		local data

		_, _, data = bin.unpack(">ca", payload)
		_, data = bin.unpack("H" .. data:len(), data)
		self:print_debug("MSGIGN", data)
		return self:recv_packet(want_msg)
	elseif(msg == MSG.SSH_MSG_UNIMPLEMENTED)
	then	-- [cf. RFC 4253 Section 11.4 (`Reserved Messages')]
		local seqno

		_, _, seqno = bin.unpack(">cI", payload)
		self:print_debug("UNIMPL", seqno)
		return false, self:set_last_error("gotunimp", seqno)
	elseif((want_msg) and (want_msg ~= msg))
	then	return false, self:set_last_error("expected", msg, want_msg)
	else	return true, payload
	end
end

--- Constructs, optionally encrypts and computes a MAC (if use of either
-- operations has been enabled beforehand,) and sends a packet from a
-- payload to the remote SSH server, employing the negotiated algorithms,
-- parameters, and derived key material for an established connection.
--@param payload The payload of the packet to send to the remote SSH server.
--@see <code>RFC 4253 Section 6 (`Binary Packet Protocol')</code>, <code>RFC 4253 Section 6.3 (`Encryption')</code>, <code>RFC 4253 Section 6.4 (`Data Integrity')</code>
--@return Either <code>true</code>, or <code>false</code> and an <code>error string</code>.
function SSH2:send_packet(payload)
	local status, error
	local calg, ctx, block_length, padding_length
	local min_packet_length, packet_length, packet, mac


	-- Ensure that either a partial or a fully established connection
	-- to an SSH server exists.
	if(not ((self.status[Status.Connecting])
	or      (self.status[Status.Connected])))
	then	return false, self:set_last_error("notconn")
	end

	-- Obtain the encryption context, and block length negotiated for the
	-- algorithm in use when encrypting packets in direction towards the
	-- server, if applying.
	calg = self.kex["encryption_C"]; block_length = 8;
	if((calg) and (calg["use"]))
	then	ctx = self.ctx["encryption_C"]
		if calg["block_size"] then block_length = calg["block_size"] end
	end

	-- Calculate the required amount of padding bytes and the resulting
	-- total /packet length/ as specified by RFC 4253 Section 6:
	-- `Note that the length of the concatenation of 'packet_length',
	--  'padding_length', 'payload', and 'random padding' MUST be a multiple
	--  of the cipher block size or 8, whichever is larger.  This constraint
	--  MUST be enforced, even when using stream ciphers.
	--  [ ... ]
	--  The minimum size of a packet is 16 (or the cipher block size,
	--  whichever is larger) bytes (plus 'mac').'
	-- Do note that a minimum padding length of 4 bytes appears to be
	-- expected in any case by at least the OpenSSH SSH2 implementation.
	-- [cf. packet.c:1205 of OpenSSH_5.0 NetBSD_Secure_Shell-20080403.]
	padding_length = block_length - ((payload:len() + 1 + 4) % block_length)
	if(padding_length < 4)
	then	padding_length = padding_length + block_length
	end

	packet_length = payload:len() + 1 + padding_length

	-- Construct the packet, compute its MAC, and encrypt it, given that
	-- either operations were negotiated and enabled beforehand,
	-- concatenating the packet and the MAC if one was computed.
	packet = bin.pack(
			">IcAA",
			packet_length, padding_length, payload,
			openssl.rand_pseudo_bytes(padding_length))

	if((self.kex["mac_C"]) and (self.kex["mac_C"]["use"]))
	then	mac = self:compute_mac(packet, true)
	end

	-- Dump the raw packet given an appropriate debugging level.
	self:dump_packet(packet, false, false)

	if((calg) and (calg["use"]))
	then	status, packet = pcall(openssl.ctx_crypt, ctx, packet)
		if not status then return status, packet end
	end

	-- Append the previously computed MAC to the end of the encrypted
	-- packet.
	if mac then packet = bin.pack("AA", packet, mac) end

	-- Dump the encrypted packet given an appropriate debugging level
	-- and if applying.
	if(calg and (calg["use"]))
	then	self:dump_packet(packet, false, true)
	end

	-- Attempt to send the now fully marshalled packet to the remote
	-- SSH server and increment the sequence number corresponding to
	-- the client-to-server direction.
	status, error = self.socket:send(packet)
	if(not status)
	then	return false, self:set_last_error("send", error)
	else	self.seq.w = self.seq.w + 1
		return true
	end
end
-- }}}
-- {{{ Public functions
--- Attempt to set up a connection on the transport layer with an SSH2 server,
-- thereafter ready to {send, receive} messages as defined in the other RFC
-- pertaning to SSH atop the former in a secure and authenticated fashion.
--	Do note that obtaining a remote SSH server's <code>host key</code>
-- does require connecting to it first as accomplished by this function.
--@param host The target remote SSH server's <code>host</code> table.
--@param port The target remote SSH server's <code>port</code> table.
--@param ident The <code>identification string</code> to send to the server, identifying the <code>protocol</code> and <code>software</code> version. Refer to <code>RFC 4253 Section 4.2 (`Protocol Version Exchange')</code> for constraints on the string or supply <code>nil</code> to indicate that the safe default of <code>SSH-2.0-OpenSSH_4.3p2</code> shall be used.
--@param timestamp_fmt The timestamp prefix format to use when debugging, defaults to <code>%H:%M:%S</code>, followed by <code>.ms</code>.
--@param timeout The <code>global</code> timeout value in <code>ms</code> that the collective total of network I/O operations may not exceed, <code>0</code> to indicate that a given response from the remote SSH server shall be waited for indefinitely, or <code>nil</code> to use the safe default value of <code>5000</code> (2 seconds.)
--@param preferred_algorithm An optionally specified table indicating one single algorithm per category that should, if possible, be preferred during algorithm negotiation, with the according categories being: <code>encryption_C</code>, <code>encryption_S</code>, <code>mac_C</code>, and <code>mac_S</code>.
--@see <code>RFC 4253, RFC 4251</code>
--@return Either <code>true</code> and an opaque <code>Session</code> table identifying the thus established connection or <code>false</code> and an <code>error string</code>.
function connect(host, port, ident, timeout, preferred_algorithm, timestamp_fmt)
	local status, error, S


	-- Set default values for arguments for which a value was not specified,
	-- in accordance with the parameter specifications listed above.
	if not ident then ident = "SSH-2.0-OpenSSH_4.3p2" end	-- XXX validate
	timeout = tonumber(timeout); if nil == timeout then timeout = 5000 end;

	-- Create a NSE socket and connect to the SSH server running on the
	-- target host currently being scanned.  Create a new Session table
	-- and record the current connection attempt's parameters in it and
	-- including the former socket given success, return failure otherwise.
	local socket = nmap.new_socket()
	if not socket then return false, "new_socket() failed unexpectedly." end

	status,
	S = new_session(
		host.ip, port.number, timeout, socket, timestamp_fmt)
	if not status then error = S; S:destroy(); return false, error; end
	S.status[Status.Connecting] = true

	S:TIMEOUT_SET()
	 status, error = socket:connect(host.ip, port.number)
	S:TIMEOUT_UPD()
	if not status then S:destroy(); return false, error; end

	-- Perform the SSH2 transport layer connection establishment procedures
	-- as specified by RFC 4253 and either return successfully or propagate
	-- any errors that occured throughout the former phase back to the
	-- caller, additionally updating the connection status in the Session
	-- table given success.
	if((not S:do_version_exchange(ident))
	or (not S:do_kex_init(preferred_algorithm))
	or (not S:do_key_exchange())
	or (not S:do_newkeys()))
	then	S:destroy()
		return false, S.last_error
	else	S.status[Status.Connected] = true
		return true, S
	end
end

-- Obtains the public host key in SSH2 format and its fingerprint
-- given a fully established connection to a remote SSH server.
--@see <code>RFC 4253 Section 6.6 (`Public Key Algorithms')<code>
--@return Either <code>true</code>, the raw <code>public host key</code>, its <code>type</code>, the bit counts of its <code>modulus</code>, and the key's <code>fingerprint</code> both as a hexadecimal, colon-separated series of tuples aswell as its raw value, or <code>false</code> and an <code>error string</code>.
function SSH2:get_hostkey()
	local status, key_type, bits, fingerprint, fingerprint_hex


	-- Ensure that a fully established connection to an SSH server exists.
	if(not self.status[Status.Connected])
	then	return false, self:set_last_error("notconn")
	end

	-- Extract the remote SSH server's public host key's signature format
	-- identifier and public exponent's bits.
	status,
	key_type, bits, _ = extract_public_key(self.kexinit["K_S"])
	if not status then return false, key end

	-- Compute the MD5 hash of the remote SSH server's public host key,
	-- producing a colon-separated sequence of hexadecimally expressed
	-- octets from the former in addition to return back to the caller.
	fingerprint = openssl.md5(self.kexinit["K_S"])
        _, fingerprint_hex = bin.unpack("H" .. fingerprint:len(), fingerprint)
        fingerprint_hex = fingerprint_hex:gsub('(..)', "%1:"):gsub(':$', "")

	return	true, self.kexinit["K_S"],
		key_type, bits, fingerprint_hex, fingerprint
end

--- Verifies whether the remote SSH server is in posession of the <code>private
-- host key</code> corresponding to the <code>public host key</code> which it
-- identified itself with during connection setup given an established
-- connection to the former by verifying the <code>signature</code> received
-- by it.
--@see <code>RFC 4253 Section 8 (`Diffie-Hellman Key Exchange')</code>
--@return Either <code>true</code> or <code>false</code> in accordance with the above conditions.
function SSH2:verify_signature()
	local status, key_type, key


	-- Ensure that a fully established connection to an SSH server exists.
	if(not self.status[Status.Connected])
	then	return false, self:set_last_error("notconn")
	end

	-- Extract the remote SSH server's public host key's signature format
	-- identifier and key parameters.
	status,
	key_type, _, key = extract_public_key(self.kexinit["K_S"])
	if not status then return false, key end

	-- XXX implement
	return false, self:set_last_error("notimpl")
end

--- Initiates following authentication process{,es} by requesting the
-- corresponding service from the remote SSH server, given a fully
-- established connection the latter.
--@see <code>RFC 4253 Section 10 (`Service Request')</code>
--@return Either <code>true</code> or <code>false</code> and an <code>error string</code>.
function SSH2:request_userauth()
	local status, error, _, service, reply, service_S


	-- Ensure that a fully established connection to an SSH server exists
	-- and that the `ssh-userauth' service has not been requested already.
	if(not self.status[Status.Connected])
	then	return false, self:set_last_error("notconn")
	end

	if(self.status[Status.RequestedUserAuth])
	then	return false, self:set_last_error("uauthreqd")
	end

	-- Send a SSH_MSG_SERVICE_REQUEST message for the `ssh-userauth'
	-- service, expecting a positive reply in return.
	service = "ssh-userauth"
	status,
	error = self:send_packet(
			bin.pack(">ca", MSG.SSH_MSG_SERVICE_REQUEST, service))
	if not status then return false, error end
	status, reply = self:recv_packet(MSG.SSH_MSG_SERVICE_ACCEPT)
	if not status then return false, reply end

	-- Compare the received service name with the corresponding equivalent
	-- as sent to the server, expecting them to match; return successfully
	-- given the latter case, otherwise return failure back to the caller.
	_, _, service_S = bin.unpack(">ca", reply)
	if(service_S ~= service)
	then	self:destroy()
		return	false,
			self:set_last_error(
				"wantservice", service, service_S)
	else	self.status[Status.RequestedUserAuth] = true
		return	true
	end
end

--- Attempt to log into the remote SSH server given a fully established
-- connection by employing the supplied <code>user-password</code> tuple
-- and the next <code>authentication method</code> that may continue
-- as per SSH parlance, which will default to <code>password</code> given
-- the first attempt to authenticate.
--
-- 	This function currently supports the following
-- <code>authentication methods</code> as per the listed RFC:
--  * <code>password</code>
--  * <code>keyboard-interactive</code>
-- Do however note that <code>keyboard-interactive</code> may intrinsically
-- hinder automation due to its inherent interactivity; no special-case
-- handling is provisioned bar responding with the supplied
-- <code>password</code> to <code>SSH_MSG_USERAUTH_INFO_REQUEST</code>
-- messages exactly once, with subsequent calls continuing the thus
-- interrupted authentication procedure until either definite success or
-- failure is indicated by the remote SSH server.
--
--	One of the following <code>Status</code> values will additionally be
-- returned by this function given failure: 
--  * <code>AuthFailureContinue</code>		-- Authentication attempt failed, may and can still continue by calling this function again
--  * <code>AuthFailurePermanent</code>	-- Authentication attempt failed and will continue to fail permanently for this remote SSH server, should consider discarding the latter
--  * <code>AuthFailure</code>			-- Authentication attempt failed, may reattempt after reconnecting to the remote SSH server
--
-- N.B.	Change of the <code>user name</code> to authenticate with midway tends
--	to be prohibited by at the very least <code>OpenSSH</code>
--	implementations, resulting in the remote SSH server closing the
--	connection with an appropriate <code>SSH_MSG_DISCONNECT</code> message.
--
-- N.B.	Paraphrasing RFC 4256 Section 3.4 (`Information Responses':)
--	`If the server intends to respond with a failure message, it MAY delay
--	 for an implementation-dependent time before sending it to the client.
--	 It is suspected that implementations are likely to make the time delay
--	 configurable; a suggested default is 2 seconds.'
--@param user The user name to authenticate with, encoded as <code>ISO-10646 UTF-8</code>.
--@param password The corresponding password to authenticate with, encoded as <code>ISO-10646 UTF-8</code>.
--@see <code>RFC 4253 Section 10 (`Service Request',) RFC 4252 -- The Secure Shell (SSH) Authentication Protocol, RFC 4256 -- Generic Message Exchange Authentication for the Secure Shell Protocol (SSH), RFC 3629 -- UTF-8, a transformation format of ISO 10646</code>
--@return Either <code>true</code> or <code>false</code>, a <code>Status</code> code, and an <code>error string</code>.
function SSH2:login(user, password)
	local _, offset, msg


	-- Ensure that a fully established connection to an SSH server exists
	-- and that the `ssh-userauth' service has been requested beforehand.
	if(not self.status[Status.Connected])
	then	return false, self:set_last_error("notconn")
	end

	if(not self.status[Status.RequestedUserAuth])
	then	return false, self:set_last_error("uauthnotreq")
	end

	-- Send a request for user authentication employing either the last used
	-- authentication method or `password' given none, the supplied user
	-- name, and possibly the supplied password unless employing
	-- `keyboard-interactive' authentication, expecting a reply either
	-- requesting additional authentication data (given the latter,) or an
	-- absolute indication of either success or failure.
	msg = bin.pack(
			">caaa",
			MSG.SSH_MSG_USERAUTH_REQUEST,
			user, "ssh-userauth",
			self.last_authentication or "password")

	-- [cf.	RFC 4252 Section 8
	--	(`Password Authentication Method: "password"')]
	if((not self.last_authentication)
	or ("password" == self.last_authentication))
	then	msg = bin.pack(">Aca", msg, 0, password)
		self:print_debug("AUTHPASS", user, password)
	-- [cf. RFC 4256 Section 3.1 (`Initial Exchange')]
	elseif("keyboard-interactive" == self.last_authentication)
	then	msg = bin.pack(">Aaa", msg, "", "")
		self:print_debug("AUTHKBD", user, "")
	else	self:destroy()
		return	false,
			Status.AuthFailurePermanent,
			self:set_last_error(
				"unknownauth", self.last_authentication)
	end

	status, error = self:send_packet(msg)
	if not status then return false, Status.AuthFailure, error end

repeat	local status, reply = self:recv_packet()
	if(not status)
	then	return false, Status.AuthFailure, reply
	else	offset, msg = bin.unpack("c", reply)
	end

	-- Determine the nature of the received reply in accordance with the
	-- above mentioned expectations to the former and w.r.t. the
	-- authentication method currently employed.
	if(MSG.SSH_MSG_USERAUTH_SUCCESS == msg)
	then	-- Absolute authentication method-independent success
		self:print_debug("AUTHSUCC")
		return true
	elseif(MSG.SSH_MSG_USERAUTH_FAILURE == msg)
	then	-- Absolute authentication method-independent failure 
		local authentications, partial_success

		-- Choose the first eligible authentication method from amongst
		-- those offered that may be used to continue authentication
		-- further and store it in the Session table.
		offset, authentications,
		partial_success = bin.unpack(">ac", reply, offset)
		self:print_debug("AUTHFAIL", authentications)

		self.last_authentication = nil
		 for method in authentications:gmatch('([^,]+),?')
		 do	if(("password" == method)
			or ("keyboard-interactive" == method))
			then	self.last_authentication = method
				break
			end
		 end
		if(not self.last_authentication)
		then	self:destroy()
			return	false,
				Status.AuthFailurePermanent,
				self:set_last_error(
					"unknownauth",
					authentications)
		end

		-- Indicate to the caller that authentication may continue.
		self:print_debug("AUTHNEXT", self.last_authentication)
		return	false,
			Status.AuthFailureContinue,
			self:set_last_error("uauthfail", authentications)
	elseif(MSG.SSH_MSG_USERAUTH_BANNER == msg)
	then	-- [cf. RFC 4252 Section 5.4 (`Banner Message')]
		local banner

		_, banner, _ = bin.unpack(">aa", reply, offset)
		banner = sanitise(banner); self:print_debug("BANNER", banner);
	elseif(MSG.SSH_MSG_USERAUTH_INFO_REQUEST == msg)
	then	-- [cf. RFC 4256 Section 3.2 (`Information Requests')
		local name, instruction, nprompts, prompt

		offset, name, instruction,
		_, nprompts = bin.unpack(">aaaI", reply, offset)
		if(1 <= nprompts)
		then	_, prompt = bin.unpack(">a", reply, offset)
			prompt = sanitise(prompt)
		end

		self:print_debug("INFOREQ", name, instruction, prompt)

		status,
		error = self:send_packet(
				bin.pack(
					">cIa",
					MSG.SSH_MSG_USERAUTH_INFO_RESPONSE,
					1, password))
		if(not status)
		then	return false, error
		else	self:print_debug("AUTHKBD", user, password)
		end
	else	-- Fail and abort any in-progress authentication procedures
		-- given an unexpected message.
		return	false,
			Status.AuthFailure,
			self:set_last_error("expected2", msg)
	end
until false
end
-- }}}

-- Make further execution dependent on successful loading of the stock NSE
-- aswell as the OpenSSL wrapper module{s,} required by this here script.
for _, modname in pairs({ "bin", "match", "nmap", "stdnse", "openssl", })
do	status, error = pcall(require, modname)
	if(not status)
	then	return	false,
			   "Failed to load the `"
			.. modname .. "' module:\n"
			.. error
	end
end

-- vim:ts=8 sw=8 tw=80 noexpandtab
-- vim:foldmethod=marker
-- vim:fileencoding=utf-8
-- vim:filetype=lua
