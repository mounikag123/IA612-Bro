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
	const match_xss_uri1 = /((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)/ &redef;
	global ascore:count &redef;
	global http_body:string &redef;

}


event http_request(c: connection, method: string, original_URI: string,unescaped_URI: string, version: string) &priority=3{
	local msg:UMessage;
	local body:UMessage;

	# GET XSS IN HTTP REQUEST HEADER
	local URI1 = unescaped_URI;
	local URI2 = original_URI;
	local src_ip = c$id$orig_h;
    local dst_ip = c$id$resp_h;

	if(match_xss_uri in URI1){
		NOTICE([$note=XSS_URI_Injection_Attack,$msg=fmt("XSS Attack from %s to destination: %s with Attack string %s", c$id$orig_h, c$id$resp_h, c$http$uri),
	    $src=src_ip,$dst=dst_ip,$identifier=cat(c$id$resp_h,c$id$resp_p)]);
		print fmt("XSS Attack from %s to destination: %s with Attack string %s", c$id$orig_h, c$id$resp_h, c$http$uri);
	}
	if(match_xss_uri1 in URI2){
		NOTICE([$note=XSS_URI_Injection_Attack,$msg=fmt("XSS Attack from %s to destination: %s with Attack string %s", c$id$orig_h, c$id$resp_h, c$http$uri),
	    $src=src_ip,$dst=dst_ip,$identifier=cat(c$id$resp_h,c$id$resp_p)]);
		print fmt("XSS Attack from %s to destination: %s with Attack string %s", c$id$orig_h, c$id$resp_h, c$http$uri);
	}
	
}


##event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
    
   ## local src_ip = c$id$orig_h;
   ## local dst_ip = c$id$resp_h;
    
##   if(match_xss_uri in data){
##	NOTICE([$note=XSS_URI_Injection_Attack,$msg=fmt("XSS Attack from %s to destination: %s with Attack data %s", c$id$orig_h, c$id$resp_h, data),
##	$src=src_ip,$dst=dst_ip,$identifier=cat(c$id$resp_h,c$id$resp_p)]);
##	print fmt("XSS Attack from %s to destination: %s with Attack string %s", c$id$orig_h, c$id$resp_h, c$http$uri);
##	}
##}
