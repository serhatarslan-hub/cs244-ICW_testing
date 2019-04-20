#!/usr/local/bin/python
# Copyright (c) 2003
# International Computer Science Institute
# All rights reserved.
#
# This file may contain software code developed for the
# TBIT project. The TBIT software carries the following copyright:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgment:
#      This product includes software developed by ACIRI, the AT&T
#      Center for Internet Research at ICSI (the International Computer
#      Science Institute). This product may also include software developed
#      by Stefan Savage at the University of Washington.
# 4. The names of ACIRI, ICSI, Stefan Savage and University of Washington
#    may not be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY ICSI AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL ICSI OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.


import sys, fileinput, string, pprint;
import commands, urlparse, httplib, urllib, htmllib, formatter, fnmatch;

_Parent = htmllib.HTMLParser;

class URLAnalyzer(_Parent):

    def __init__(self, *args, **kw):
        apply(_Parent.__init__, (self,) + args, kw);
        self.imgs = [];

    def handle_image(self, src, *args):
        self.imgs.append(src);


# Define a subclass of FancyURLopener to ignore sites
# that require user authentication

class MyFancyURLopener(urllib.FancyURLopener):

    def prompt_user_passwd(self, username, passwd):
        return;

    
def GetURLIPAddr(url):

    """ Determine IP Address of requested URL"""

    scheme, hostname, path, params, query, frag = urlparse.urlparse(url);
    if not hostname:
        l = string.split(path, "/");
        hostname = l[0];

    cmd = "host " + hostname;
    
    s,o = commands.getstatusoutput(cmd);
    ipaddrs = [];

    if not s:
        l = string.split(o, "\n");
        for l_el in l:
            if string.find(l_el, "address") > 0:
                l_el_fields = string.split(l_el);
                ipaddrs.append(l_el_fields[-1]);

    return ipaddrs;    


def ProcessLinks(url_opener, url, link_list, num_links, thresh_size, seen_hosts):

    if not num_links:
        return [];

    processed_links = [];    
    
    # Keep track of number of processed links    
    n = 0; 
    for link in link_list:

        l_url = urlparse.urljoin(url, link);
        print "\tProcessing link:", l_url;        

        try:
            u = url_opener.open(l_url);            
            actual_url = u.geturl();
            scheme, host, path, params, query, fragment = urlparse.urlparse(actual_url);
        
            # Account for unique hosts only
            if seen_hosts.has_key(host):
                continue;

            file = u.read();
            link_size = len(file);
        
        except:
            print "Cannot process link:", l_url;
            continue;

        if link_size >= thresh_size:
            processed_links.append((actual_url, link_size));
            seen_hosts[host] = 1;
            n += 1;            

        if n == num_links:
            break;

    return(processed_links);

def ProcessImages(url, image_list, num_imgs, thresh_size):

    if not num_imgs:
        return [];
    
    processed_images = [];
    n = 0;
    
    for image in image_list:

        print "\tProcessing image:", image;
        i_url = urlparse.urljoin(url, image);
        try:
            u = urllib.urlopen(i_url);
            actual_url = u.geturl();
            file = u.read();
            image_size = len(file);
            
        except:
            image_size = -1;

        if image_size >= int(thresh_size):
            processed_images.append((actual_url, image_size))
            n += 1;

        if n >= num_imgs:
            break;

    return(processed_images);


def GetURLInfo(url_opener, url_file, output_file, thresh_size, num_links, num_imgs):

    try:
        f = open(output_file, 'w');
    except IOError, msg:
        print "Cannot open output file:", msg;
        return;

    # Keep track of hosts already accouted for
    seen_hosts = {};

    # Process input URL list
    for url in fileinput.input(url_file):

        print "Processing site:", string.strip(url);

        try:
            # Grab URL and open it
            url = string.strip(url);
            u = url_opener.open(url);

            # Account for HTTP redirections
            actual_url = u.geturl();  

            # Parse URL (grab links and images)
            h = URLAnalyzer(formatter.NullFormatter());
            file = u.read();
            h.feed(file);

            # Determine URL size (from downloaded file)
            this_url_size = len(file);

        except:
            print "Cannot process:", url;
            continue;

        print "URL size:", this_url_size;
        
        ### Determine IP Address
        scheme, host, path, params, query, fragment = urlparse.urlparse(actual_url);
        if seen_hosts.has_key(host):
            continue;

        # Get set of IP addresses
        ipaddrs = GetURLIPAddr(string.split(host,":")[0]);
        pprint.pprint(ipaddrs);
        
        n = 0;
        if (num_links > 0) and (this_url_size >= thresh_size):

            if not path:
                path = "/";

            if query:
                query = "?" + query;
            if not ipaddrs:
                f.write(host + "\t" + "\"" + path +  query + params + fragment + "\"\t" + str(-1) + "\t" + str(this_url_size) + "\n");
                f.flush();
            else:
                for ipaddr in ipaddrs:
                    f.write(host + "\t" + "\"" + path +  query + params + fragment + "\"\t" + ipaddr +\
                            "\t" + str(this_url_size) + "\n");
                    f.flush();                    

                
            seen_hosts[host] = 1;
            n = 1;

        processed_links = ProcessLinks(url_opener, actual_url, h.anchorlist, num_links - n, thresh_size, seen_hosts);
        
        for (link, size) in processed_links:

            if size > thresh_size:
                scheme, host, path, params, query, fragment = urlparse.urlparse(link);
                if not path:
                    path = "/";
                if query:
                    query = "?" + query;                    
                link_ipaddrs = GetURLIPAddr(host);
                if not link_ipaddrs:
                    f.write(host + "\t" + "\"" + path + query + fragment + "\"\t" + str(-1) + "\t" + str(size) + "\n");
                    f.flush();
                else:
                    for link_ipaddr in link_ipaddrs:
                        f.write(host + "\t" + "\"" + path + query + fragment + "\"\t" + link_ipaddr +\
                                "\t" + str(size) + "\n");
                        f.flush();                        
        
        if num_imgs > 0:
            f.write("\tIMAGES:\n");            
            processed_images = ProcessImages(actual_url, h.imgs, num_imgs, thresh_size);                    
            for (image, size) in processed_images:
                f.write("\t\t" + image + " - " + str(size) + "\n");
                f.flush();                


    f.close();


def Usage():
    print """Run:\n
    large_url_finder.py <url_file> <output_file> <threshold_size> <num_links> <num_images>\n\n""";
    sys.exit();

    
def main():

    if len(sys.argv) < 6:
        Usage();
        sys.exit();
        
    url_file = sys.argv[1];
    output_file = sys.argv[2];
    threshhold = int(sys.argv[3]);
    num_links = int(sys.argv[4]);
    num_imgs = int(sys.argv[5]);

    url_opener = MyFancyURLopener({});

    GetURLInfo(url_opener, url_file, output_file, threshhold, num_links, num_imgs);


if __name__ == "__main__":
    main();








