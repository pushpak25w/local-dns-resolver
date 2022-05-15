import logging
import argparse
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
from dns.exception import DNSException,Timeout

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has IPV4 address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

count=0

def update_cache(response: dns.message.Message,DNS_CACHE: dict)->None:
	domain_name = response.authority[0].to_text().split(" ")[0]
	rrsets = response.additional
	for rrset in rrsets:
		for rr_ in rrset:
			if rr_.rdtype == dns.rdatatype.A:
				DNS_CACHE[domain_name] = str(rr_)

def lookup_additional(response,
					dnsName: dns.name.Name,
					qtype: dns.rdata.Rdata,
					resolved: bool,
					DNS_CACHE :dict):
	rrsets=response.additional
	for rrset in rrsets:
		for rr in rrset:
			if rr.rdtype==dns.rdatatype.A:
				print("lookup_additional ",rr)
				response,resolved=lookup_recurse(dnsName,qtype,str(rr),resolved,DNS_CACHE)
			if resolved:
				break
		if resolved:
			break
	return response,resolved

def lookup_authority(response: dns.message.Message,
					dnsName: dns.name.Name,
					qtype: dns.rdata.Rdata,
					resolved: bool,
					DNS_CACHE :dict):
	rrsets=response.authority
	nsIP=""
	for rrset in rrsets:
		for rr in rrset:
			if rr.rdtype==dns.rdatatype.NS:
				nsIP=DNS_CACHE.get(str(rr))
				if not nsIP:
					ns_A_records=lookup(str(rr),dns.rdatatype.A,DNS_CACHE)
					nsIP=str(ns_A_records.answer[0][0])
					DNS_CACHE[str(rr)]=nsIP
				print("lookup_authority ",rr)
				response,resolved=lookup_recurse(dnsName,qtype,nsIP,resolved,DNS_CACHE)
			elif rr.rdtype==dns.rdatatype.SOA:
				resolved=True
				break
		if resolved:
			break
	return response,resolved


def collect_info(domain: str,DNS_CACHE: dict)->dict:
	final_res={}
	dnsName=dns.name.from_text(domain)
	
	# lookup CNAME
	response=lookup(dnsName,dns.rdatatype.CNAME,DNS_CACHE)
	cnames=[]
	for answers in response.answer:
		for ans in answers:
			cnames.append({"name": ans,"alias": name})

	# lookup A
	response=lookup(dnsName,dns.rdatatype.A,DNS_CACHE)
	A_records=[]
	for answers in response.answer:
		A_name=answers.name
		for ans in answers: 
			if ans.rdtype==1:
				A_records.append({"name":A_name,"address":str(ans)})

	# lookup AAAA
	response=lookup(dnsName,dns.rdatatype.AAAA,DNS_CACHE)
	AAAA_records=[]
	for answers in response.answer:
		AAAA_name=answers.name
		for ans in answers: 
			if ans.rdtype==28:
				AAAA_records.append({"name":AAAA_name,"address":str(ans)})

	# lookup MX
	response=lookup(dnsName,dns.rdatatype.MX,DNS_CACHE)
	MX_records=[]
	for answers in response.answer:
		MX_name=answers.name
		for ans in answers: 
			if ans.rdtype==15:
				MX_records.append({"name":MX_name,
									"preference":ans.preference,
									"exchange":str(ans.exchange)})

	final_res["CNAME"]=cnames
	final_res["A"]=A_records
	final_res["AAAA"]=AAAA_records
	final_res["MX"]=MX_records

	DNS_CACHE['response_cache'][domain]=final_res

	return final_res


def lookup_recurse(dnsName: dns.name.Name,
					qtype: dns.rdata.Rdata,
					ip: str,
					resolved: bool,
					DNS_CACHE: dict):
	global count
	count+=1
	query=dns.message.make_query(dnsName,qtype)
	try:
		print(ip)
		response=dns.query.udp(query,ip,3)
		if response.answer:
			resolved=True
			return response,resolved
		
		elif response.additional:
			if response.authority:
				update_cache(response,DNS_CACHE)
			# print(response.additional)
			# print(response,dnsName,qtype,resolved,DNS_CACHE)
			response,resolved=lookup_additional(response,dnsName,qtype,resolved,DNS_CACHE)
			
		elif response.authority and resolved==False:
			response,resolved=lookup_authority(response,dnsName,qtype,resolved,DNS_CACHE)
		
		return response,resolved
	except Timeout:
		logging.debug("Timeout")
		return dns.message.Message(),False
	except DNSException:
		logging.debug(ip," DNSException")
		return dns.message.Message(),False


def lookup(dnsName: dns.name.Name,
			qtype: dns.rdata.Rdata,
			DNS_CACHE: dict)->dns.message.Message:
	resolved=False
	for root_server_ip in ROOT_SERVERS:
		ip_in_cache=""
		toFind=str(dnsName)
		dot=toFind.find('.')
		while ip_in_cache!="" and dot!=-1:
			ip_in_cache=DNS_CACHE.get(toFind)
			toFind=str(toFind)[dot+1:]
			dot=toFind.find('.')
		if ip_in_cache:
			ip=ip_in_cache
			logging.debug("found ip in cache")
		else:
			ip=root_server_ip
		try:
			print("lookup ",ip)
			response,resolved=lookup_recurse(dnsName,qtype,ip,resolved,DNS_CACHE)
			if response.answer:
				ans_type=response.answer[0].rdtype
				if qtype!=dns.rdatatype.CNAME and ans_type==dns.rdatatype.CNAME:
					dnsName=dns.name.from_text(str(response.answer[0][0]))
					resolved=False
					logging.debug("looking up cname")
					response=lookup(dnsName,qtype,DNS_CACHE)
				return response
			elif response.authority and response.authority[0].rdtype==dns.rdatatype.SOA:
				logging.debug("got SOA")
				break
		except Timeout:
			logging.debug("Timeout")
			return dns.message.Message(),False
		except DNSException:
			logging.debug(ip," DNSException")
			return dns.message.Message(),False
	return response

def print_info(info: dict)->None:
	for rtype,fmtStr in FORMATS:
		for inf in info.get(rtype,[]):
			print(fmtStr.format(**inf))


def main():
	global count
	DNS_CACHE={}
	DNS_CACHE['response_cache']={}
	arg_parser=argparse.ArgumentParser()
	arg_parser.add_argument("name", nargs="+",help="DNS name(s) to look up")
	args=arg_parser.parse_args()
	for domain in args.name:
		count=0
		if domain in DNS_CACHE['response_cache']:
			print_info(DNS_CACHE['response_cache'].get(domain))
		else:
			print_info(collect_info(domain,DNS_CACHE))
		logging.debug("count %s", count)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()