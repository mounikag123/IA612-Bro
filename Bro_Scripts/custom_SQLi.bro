<<<<<<< HEAD

#@load base/protocols/http;
module HTTP;

export {
	
=======
@load base/frameworks/notice
@load base/protocols/ssh
@load base/protocols/http

module HTTP;

export {
	redef enum Notice::Type += {
		SQLi_URI_Injection_Attack,
		SQLi_Post_Injection_Attack,
	};
	
 	## URL message input
	type UMessage: record{
	    text: string; ##< The actual URL body
	};
 
>>>>>>> working
	const sql_injection_uri = 
		  /[\?&][^[:blank:]\x00-\x37\|]+?=[\-[:alnum:]%]+([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x37]|\/\*.*?\*\/|\)?;)+.*?([hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x37]|\/\*.*?\*\/)+/
		| /[\?&][^[:blank:]\x00-\x37\|]+?=[\-0-9%]+([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x37]|\/\*.*?\*\/|\)?;)+([xX]?[oO][rR]|[nN]?[aA][nN][dD])([[:blank:]\x00-\x37]|\/\*.*?\*\/)+['"]?(([^a-zA-Z&]+)?=|[eE][xX][iI][sS][tT][sS])/
		| /[\?&][^[:blank:]\x00-\x37]+?=[\-0-9%]*([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x37]|\/\*.*?\*\/)*(-|=|\+|\|\|)([[:blank:]\x00-\x37]|\/\*.*?\*\/)*([0-9]|\(?[cC][oO][nN][vV][eE][rR][tT]|[cC][aA][sS][tT])/
		| /[\?&][^[:blank:]\x00-\x37\|]+?=([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x37]|\/\*.*?\*\/|;)*([xX]?[oO][rR]|[nN]?[aA][nN][dD]|[hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[rR][eE][gG][eE][xX][pP]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x37]|\/\*.*?\*\/|[\[(])+[a-zA-Z&]{2,}/
		| /[\?&][^[:blank:]\x00-\x37]+?=[^\.]*?([cC][hH][aA][rR]|[aA][sS][cC][iI][iI]|[sS][uU][bB][sS][tT][rR][iI][nN][gG]|[tT][rR][uU][nN][cC][aA][tT][eE]|[vV][eE][rR][sS][iI][oO][nN]|[lL][eE][nN][gG][tT][hH])\(/
		| /\/\*![[:digit:]]{5}.*?\*\// 
	&redef;
}


event http_request(c:connection,method: string, original_URI: string, unescaped_URI: string, version: string) {
<<<<<<< HEAD
	
    local URI1 = unescaped_URI;
    local URI2 = original_URI;
=======
	local msg:UMessage;
	local body:UMessage;
	
    local URI1 = unescaped_URI;
    local URI2 = original_URI;
    local src_ip = c$id$orig_h;
    local dst_ip = c$id$resp_h;
>>>>>>> working

    if (sql_injection_uri in URI2 ){
		print fmt("ID: %s SQL INJECTION DETECTED in %s from IP: %s | String: %s ", c$uid, method, c$id$orig_h, unescaped_URI);
		#print fmt("ORIG %s", original_URI);
<<<<<<< HEAD
=======
		NOTICE([$note=SQLi_URI_Injection_Attack,$msg=fmt("XSS Attack from %s to destination: %s with Attack string %s", c$id$orig_h, c$id$resp_h, c$http$uri),
	    $src=src_ip,$dst=dst_ip]);
>>>>>>> working
    }
	  if (sql_injection_uri in URI1 ){
		print fmt("ID: %s SQL INJECTION DETECTED in %s from IP: %s | String: %s ", c$uid, method, c$id$orig_h, unescaped_URI);
		#print fmt("ORIG %s", original_URI);
<<<<<<< HEAD
    }


=======
		NOTICE([$note=SQLi_URI_Injection_Attack,$msg=fmt("XSS Attack from %s to destination: %s with Attack string %s", c$id$orig_h, c$id$resp_h, c$http$uri),
	    $src=src_ip,$dst=dst_ip]);
    }

>>>>>>> working
}
