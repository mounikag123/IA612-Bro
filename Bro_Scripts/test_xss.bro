@load base/frameworks/notice
@load base/protocols/ssh
@load base/protocols/http

module HTTP;
export {
 redef enum Notice::Type += {
 XSS_URI_Injection_Attack,
 XSS_Post_Injection_Attack,
 };

 ## URL message input
 type UMessage: record{
	text: string; ##< The actual URL body
	};
	
const match_xss_uri = /[<>]/ &redef;
const match_xss_uri1 = /[<>]/ &redef;
const match_xss_body = /[3C3E]/ &redef;
global ascore:count &redef;
global http_body:string &redef;

redef record Info += {
 ## Variable names extracted from all cookies.
	post_vars: vector of string &optional &log;
	};
}


event http_request(c: connection, method: string, original_URI: string,unescaped_URI: string, version: string) &priority=3{
	local msg:UMessage;
	local body:UMessage;
	ascore = 1;
	# GET XSS IN HTTP REQUEST HEADER
	local URI1 = unescaped_URI;
	local URI2 = original_URI;

	if(match_xss_uri in URI1){
		++ascore;
	if(match_xss_uri1 in URI2)
		++ascore;
	}
	ascore = 3;
	if ( ascore >= 3){
		NOTICE([$note=XSS_URI_Injection_Attack,
		$conn=c,
		$msg=fmt("XSS Attack from %s to destination: %s with Attack string %s", c$id$orig_h, c$id$resp_h, c$http$uri)]);
		print fmt("XSS Attack from %s to destination: %s with Attack string %s", c$id$orig_h, c$id$resp_h, c$http$uri);
	}
}
