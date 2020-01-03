#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string>
#include <map>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <sys/stat.h>
#include <utility>
#include "Mimetype.h"
#include <fstream>
#include <sys/types.h>
#include <dirent.h>
#include <ctime>
#include <set>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>

using namespace std;


typedef struct dirent dirent;
typedef struct response_packet
{
	string status;
	string content_type;
	string content;
	string other;
} rpacket;


map<string, string> proc_first_header(string header)
{
	stringstream ss(header);
	map<string, string> result_map;
	string proc_line, path;
	getline(ss,proc_line,' ');
	result_map["header_Method"] = proc_line;
	getline(ss,path,' ');
	getline(ss,proc_line,' ');
	result_map["header_Protocol"] = proc_line;
	if(path.find('?') < path.length())
	{
		ss = stringstream(path);
		getline(ss,proc_line,'?');
		result_map["header_Path"] = proc_line;
		getline(ss,proc_line);
		result_map["header_Get_Parameter"] = proc_line;
	}
	else
	{
		result_map["header_Path"] = path;
	}
	/*map<string, string>::iterator itr;
	for(itr = result_map.begin(); itr != result_map.end(); itr++)
	{
		cout << "|" << itr->first << "| => |" << itr->second << "|" << endl; 
	}*/
	return result_map;
}

map<string, string> preproc(char *buf) /*pre-process packet to map*/
{
	stringstream ss(buf);
	string proc_line, content;
	int find_pos;
	map<string, string> result_map, header_map;
	if (buf != NULL)
	{
		getline(ss,proc_line,'\n');
		//result_map["first_line_header"] = proc_line;
		if(proc_line[proc_line.length()-1] == '\r')
		{
			proc_line.erase(proc_line.length()-1, 1);
		}
		header_map = proc_first_header(proc_line);
		result_map.insert(header_map.begin(), header_map.end());
		proc_line.clear();
		while(getline(ss,proc_line,'\n')){
			if(proc_line != "\r"){
				find_pos = proc_line.find(":");
				//cout << "findpos: " << find_pos << endl;
				if(find_pos >= 0){
					content = proc_line.substr(0, find_pos);
					proc_line.erase(0, find_pos + 2);
					//cout << content << " ::: " << proc_line << endl;
					if(proc_line[proc_line.length()-1] == '\r')
					{
						proc_line.erase(proc_line.length()-1, 1);
						if(result_map[content].empty())
							result_map[content] = proc_line;
					}
					else
					{
						if(result_map[content].empty())
							result_map[content] = proc_line;
					}
				}
				proc_line.clear();
			}
			else{
				//printf("last line space:\n");
				//get content length and set content to proc_line string
				if( !result_map["Content-Length"].empty() && ss >> setw(stoi(result_map["Content-Length"])) >> proc_line) 
				{
					//cout << proc_line << endl;
					result_map["post_all_content"] = proc_line;
					break;
				}
				proc_line.clear();
			}
		}
	}
	else{ cout << "buf is NULL" << endl; }
	/*map<string, string>::iterator itr;
	for(itr = result_map.begin(); itr != result_map.end(); itr++)
	{
		cout << "|" << itr->first << "| => |" << itr->second << "|" << endl; 
	}*/
	return result_map;
}

rpacket proc_failed(int error_code)
{
	rpacket result;
	result.content_type = "text/html";
	if(error_code == 404)
	{
		result.status = "404 Not Found";
		result.content = "<h1>404 Not Found</h1>";
	}
	else if(error_code == 403)
	{
		result.status = "403 Forbidden";
		result.content = "<h1>403 Forbidden</h1>";
	}
	else if(error_code == 500)
	{
		result.status = "500 Internal Server Error";
		result.content = "<h1>500 Internal Server Error</h1>";
	}
	else
	{
		result.status = "500 Internal Server Error";
		result.content = "<h1>500 Internal Server Error</h1>";
	}
	return result;
}

void parse_response_header(rpacket content, int fd)
{
	string final_response = "";
	if(!content.status.empty())
	{
		final_response += "HTTP/1.1 " + content.status + "\r\n";
		final_response += "Content-Type: " + content.content_type + "\r\n";
		final_response += "Content-Length: " + to_string((content.content).length()) + "\r\n";
		final_response += "Connection: close\r\n";
		if (!content.other.empty()) final_response += content.other;
		final_response += "\r\n" + content.content ;
	}
	else
	{
		final_response += "HTTP/1.1 500 Internal Server Error\r\n";
		final_response += "Content-Type: text/html\r\n";
		final_response += "Content-Length: 34\r\n";
		final_response += "Connection: close\r\n";
		final_response += "\r\n<h1>500 Internal Server Error</h1>";
	}
	if(send(fd, final_response.c_str(), final_response.length(), 0) < 0) {
		perror("send");
		exit(-1);
	}
}

void parse_content(string final_response, int fd)
{
	if(send(fd, final_response.c_str(), final_response.length(), 0) < 0) {
		perror("send");
		exit(-1);
	}
}

void parse_only_header(rpacket content, int fd, int clength)
{
	string final_response = "";
	if(!content.status.empty())
	{
		final_response += "HTTP/1.1 " + content.status + "\r\n";
		final_response += "Content-Type: " + content.content_type + "\r\n";
		final_response += "Content-Length: " + to_string(clength) + "\r\n";
		final_response += "Connection: close\r\n";
	}
	if(send(fd, final_response.c_str(), final_response.length(), 0) < 0) {
		perror("send");
		exit(-1);
	}
}

string convert_stmod(struct stat fileStat)
{
	string result = "";
	result += (S_ISDIR(fileStat.st_mode)) ? "d" : "-";
	result += (fileStat.st_mode & S_IRUSR) ? "r" : "-";
	result += ( (fileStat.st_mode & S_IWUSR) ? "w" : "-");
	result += ( (fileStat.st_mode & S_IXUSR) ? "x" : "-");
	result += ( (fileStat.st_mode & S_IRGRP) ? "r" : "-");
	result += ( (fileStat.st_mode & S_IWGRP) ? "w" : "-");
	result += ( (fileStat.st_mode & S_IXGRP) ? "x" : "-");
	result += ( (fileStat.st_mode & S_IROTH) ? "r" : "-");
	result += ( (fileStat.st_mode & S_IWOTH) ? "w" : "-");
	result += ( (fileStat.st_mode & S_IXOTH) ? "x" : "-");
	return result;
}

void get_file(string filepath, map<string, string> all_map, int fd)
{
	rpacket result;
	if(filepath.find_last_of(".") < filepath.length()){ //get file extension
		string ext = filepath.substr( filepath.find_last_of(".") + 1 );
		if(ext == "cgi")
		{
			int c2p_link[2], p2c_link[2];
			pid_t pid;
			char foo[4096];
			if (pipe(c2p_link)==-1 || pipe(p2c_link) == -1)
			{
				perror("pipe");
				exit(-1);
			}
			if ((pid = fork()) == -1)
			{
				perror("fork");
				exit(-1);
			}
			if(pid == 0) {
				//child
				dup2 (c2p_link[1], 1);
				close(c2p_link[0]);
				close(c2p_link[1]);
				dup2 (p2c_link[0], 0);
				close(p2c_link[1]);
				close(p2c_link[0]);
				char *c_argv[] = { (char *)filepath.c_str(), "t=123", NULL }; //change to cgi
				const char **c_envp = new const char*[16];
				string parse_env_cgj[15] =
				{
					("REMOTE_ADDR=" + all_map["Host"]),
					("SERVER_PROTOCOL=" + all_map["header_Protocol"]),
					("REQUEST_METHOD=" + all_map["header_Method"]),
					("QUERY_STRING=" + all_map["header_Get_Parameter"]),
					("REQUEST_URI=" + all_map["header_Path"] + "?" + all_map["header_Get_Parameter"]),
					("SCRIPT_NAME=" + all_map["header_Path"]),
					("CONTENT_LENGTH=" + all_map["Content-Length"]),
					("CONTENT_TYPE=" + all_map["Content-Type"]),
					"GATEWAY_INTERFACE=CGI/1.1",
					("REMOTE_PORT=" + all_map["client_port"]),
					"PATH=/bin:/usr/bin:/usr/local/bin",
					("HTTP_ACCEPT=" + all_map["Accept"]),
					("HTTP_ACCEPT_ENCODING=" + all_map["Accept-Encoding"]),
					("HTTP_ACCEPT_LANGUAGE=" + all_map["Accept-Language"]),
					("HTTP_USER_AGENT=" + all_map["User-Agent"])
				};
				for(int i=0; i<15; i++)
				{
					c_envp[i] = parse_env_cgj[i].c_str();
				}
				c_envp[15]=NULL;
				execve(c_argv[0], &c_argv[1], (char **)c_envp);
				exit(0);
			}
			else {
				close(p2c_link[0]);
				close(c2p_link[1]);
				write(p2c_link[1], (all_map["post_all_content"]+"\n").c_str(), all_map["post_all_content"].length()+1);
				wait(NULL);
				int nbytes = read(c2p_link[0], foo, sizeof(foo));
				result.status = "200 OK";
				stringstream strm;
				strm.rdbuf()->pubsetbuf(foo, strlen(foo));
				string conttype, tmpstr;
				getline(strm,conttype);
				tmpstr = strm.str();
				tmpstr.erase(0, conttype.length()+2);
				int contlen = conttype.find(':');
				if(contlen > 0){
					conttype = conttype.substr(conttype.find(':')+2);
					result.content_type = conttype;
					result.content = tmpstr;
				}
				else{
					result.content_type = "text/plain";
					result.content = strm.str();
				}
				parse_response_header(result, fd);
				//printf("p Output: (%.*s)\n", nbytes, foo);
  			}
			return;
		}
		//cout << "file ext: " << ext << endl;
		string Mimetype = "";
		//convert to MIME type
		int len;
		for(int i=0;extensions[i].ext!="";i++) {
			if(ext == extensions[i].ext) {
				Mimetype = extensions[i].ext;
				break;
			}
    	}
		if(Mimetype == "")
		{
			Mimetype = "UnKnowType";
		}
		ifstream read_file(filepath.c_str());
		if(!read_file.fail()) //read file success
		{
			result.status = "200 OK";
			result.content_type = Mimetype;
			string final_response = "";
			read_file.seekg (0, read_file.end);
			unsigned long long int length = read_file.tellg();
			//length--;
			final_response += "HTTP/1.1 " + result.status + "\r\n";
			final_response += "Content-Type: " + result.content_type + "\r\n";
			final_response += "Content-Length: " + to_string(length) + "\r\n";
			final_response += "Connection: close\r\n\r\n";
			parse_content(final_response, fd);
			read_file.seekg (0, read_file.beg);
			unsigned long long count = 0, nowint;
			char buffer[1024*1024+1];
			while(1) {
				nowint = ((length - count) >= (1024*1024)) ? (1024*1024) : (length - count);
				//cout <<"count: " << count << endl;
				read_file.read(buffer, nowint);
				count += nowint;
				buffer[nowint] = 0;
				if(send(fd, buffer, nowint, 0) < 0) {
					perror("send");
					exit(-1);
				}
				if(count == (length) || read_file.eof())
				{
					//parse_content(string(NULL),fd);
					break;
				}
    		}
			//cout << "content: " << count << endl;
		}
		else //read file faild
		{
			cout << "Can't open file: " << filepath << endl;
			result = proc_failed(404);
			parse_response_header(result, fd);
		}
	}
	else //can't get file extension
	{
		cout << "Can't get file ext: " << filepath << endl;
		result = proc_failed(404);
		parse_response_header(result, fd);
	}
}

/*string proc_dir_ls(vector<string> list_dir_set, const string filepath)//non-use
{
	char buffer[256];
	string cmd = "ls -al "+filepath;
	FILE* pipe = popen(cmd.c_str(), "r");
	vector<string> ls_result;
	string result = "";
	if (!pipe) throw runtime_error("popen() failed!");
	try {
        while (fgets(buffer, sizeof buffer, pipe) != NULL) {
			string ss(buffer);
			ls_result.push_back(ss);
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
	pclose(pipe);
	ls_result.erase(ls_result.begin());
	vector<string>::iterator ls_vec_itr;
	vector<string>::iterator name_set_itr;
	if(ls_result.size() != list_dir_set.size())
	{
		cout << "size not same " << "ls vec: "<< ls_result.size() << " name set: " << list_dir_set.size() << endl;
		return "";
	}
	string tmps, rept;
	for(ls_vec_itr=ls_result.begin(), name_set_itr = list_dir_set.begin(); \
	ls_vec_itr!=ls_result.end() && name_set_itr != list_dir_set.end(); \
	name_set_itr++,ls_vec_itr++)
	{
		tmps=*ls_vec_itr;
		rept = "<a href=\"" + *name_set_itr + "\">" + *name_set_itr + "</a>";
		cout << "f: " << *name_set_itr << "  " << *ls_vec_itr << endl;
		tmps += rept;
		result += tmps;
	}
	return result;
}*/

void get_dir(const string filepath, map<string, string> all_map, int fd)
{
	rpacket result;
	if(filepath[filepath.length()-1] != '/') //without slash return 301
	{
		result.status = "301 Moved Permanently";
		result.content_type = "text/html";
		result.content = "<h1>301 Permanently</h1>";
		result.other = "Location: http://" + all_map["Host"] + all_map["header_Path"] + "/";
		if(!all_map["header_Get_Parameter"].empty())
		{ result.other += "?" + all_map["header_Get_Parameter"] + "\r\n"; }
		else { result.other += "\r\n"; }
		parse_response_header(result, fd);
		return;
	}
	DIR *dirp;
	struct stat statbuf;
	if ((dirp = opendir(filepath.c_str())) != NULL)  // open dir success
	{
		//cout << "opendir success" << endl;
		if(lstat( (filepath + "index.html").c_str() , &statbuf) == 0) //index.html exist
		{
			ifstream read_file((filepath + "index.html").c_str());
			if(read_file.fail()){
				parse_response_header(proc_failed(403),fd); //index.html inaccess return 403
				return;
			} 
			get_file((filepath + "index.html"), all_map, fd); //get file to return index.html
			return;
		}
		else
		{
			dirent *dp;
			result.status = "200 OK";
			result.content_type = "text/html";
			string allcont = "";
			//vector<string> list_dir_set;
			map<string, string>list_dir_map;
			do
			{
				if ((dp = readdir(dirp)) != NULL) 
				{
					string d_name(dp->d_name);
					//list_dir_set.push_back(d_name);
					struct stat statbuffer;
					lstat( (filepath+d_name).c_str() , &statbuffer);
					//stat(dp->d_name, &statbuf);
					string stres = convert_stmod(statbuffer);
					char str_size[512] = "";
					char str_time[32];
					tm * ptm = std::localtime(&statbuffer.st_mtime);
					strftime(str_time, 32, "%b %e %H:%M ", ptm); 
					snprintf(str_size, sizeof str_size, "%3lu %4ld %4ld %10zu %13s", statbuffer.st_nlink, (long)statbuffer.st_uid, (long)statbuffer.st_gid, statbuffer.st_size, str_time);
					//cout << "uid:" << statbuffer.st_nlink << endl;
					stres += " "+string(str_size);
					list_dir_map[d_name] = stres;
				}
			}while (dp != NULL);
			//allcont = proc_dir_ls(list_dir_set, filepath);
			map<string, string>::iterator map_it;
			for(map_it = list_dir_map.begin(); map_it != list_dir_map.end(); map_it++)
			{
			        allcont += map_it->second + " <a href=\"" + map_it->first + "\">"+ map_it->first +"</a>\n";
			}
			result.content = "<html>\r\n\
			<head>\r\n\
			<meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\"/>\r\n\
			<title>/net/faculty/chuang/chuang/courses/unixprog/resources/hw4_web/testcase/dir2</title>\r\n\
			<style>\r\n\
			body {\r\n\
				font-family: monospace;\r\n\
				white-space: pre;\r\n\
			}\r\n\
			</style>\r\n\
			</head>\r\n\
			<body>\r\n\
			<hr/>\r\n" + allcont + "<hr/>\r\n\
			</body>\r\n\
			</html>";
		}
		(void) closedir(dirp);
		parse_response_header(result, fd);
		return;
	}
	else //dir not readable
	{
		if(lstat( (filepath + "index.html").c_str() , &statbuf) == 0) //index.html exist
		{
			ifstream read_file((filepath + "index.html").c_str());
			if(read_file.fail()){
				parse_response_header(proc_failed(404), fd); //index.html inaccess return 403
				return;
			}
			get_file((filepath + "index.html"), all_map, fd); //get file to return index.html
		}
		else
		{
			result = proc_failed(404);
			parse_response_header(result, fd);
			return;
		}
	}
}





void serv_client(int fd, struct sockaddr_in *sin, string base_path) {
	int len, client_port;
	char buf[1024*1024];
	struct stat statbuf;
	map<string, string> packet_map;
	printf("connected from %s:%d\n",
		inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
	client_port = ntohs(sin->sin_port);
	if((len = recv(fd, buf, sizeof(buf), 0)) > 0) {
		packet_map = preproc(buf);
		packet_map["client_port"] = to_string(client_port);
		/*map<string, string>::iterator itr;
		for(itr = packet_map.begin(); itr != packet_map.end(); itr++)
		{
			cout << "|" << itr->first << "| => |" << itr->second << "|" << endl; 
		}*/
		//printf("%s", buf);
		if(!packet_map["header_Path"].empty()){
			if(lstat( (base_path + packet_map["header_Path"]).c_str() , &statbuf) != 0) //file or dir not exist
			{
				cout << "file or dir Not exist: " << base_path + packet_map["header_Path"] << endl;
				parse_response_header(proc_failed(403), fd);
			}
			else //file or dir  exist
			{
				if(S_ISREG(statbuf.st_mode)) //is a regular file
				{
					//cout << "----\nThis is a regular file: "<< base_path + packet_map["header_Path"] <<"\n----\n";
					get_file(base_path + packet_map["header_Path"], packet_map, fd);
				}
				else if(S_ISDIR(statbuf.st_mode)) //is a directory
				{
					//cout << "----\nThis is a directory: "<< base_path + packet_map["header_Path"] <<"\n----\n";
					get_dir(base_path + packet_map["header_Path"], packet_map, fd);
				}
			}
		}
		else
		{
			cout << "Can't detect the path in url" << endl;
		}
	}
	printf("disconnected from %s:%d\n",
		inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
	return;
}


int main(int argc, char *argv[]) {
	pid_t pid;
	int fd, pfd;
	unsigned val;
	struct sockaddr_in sin, psin;
	if(argc < 3) {
		fprintf(stderr, "usage: %s port path\n", argv[0]);
		return(-1);
	}
	cout << "port: " << argv[1] << " path: " << argv[2] << endl;
	string base_path = argv[2];
	signal(SIGCHLD, SIG_IGN);
	if((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		return(-1);
	}
	val = 1;
	if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
		perror("setsockopt");
		return(-1);
	}

	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(atoi(argv[1]));
	if(bind(fd, (struct sockaddr*) &sin, sizeof(sin)) < 0) {
		perror("bind");
		return(-1);
	}
	if(listen(fd, SOMAXCONN) < 0) {
		perror("listen");
		return(-1);
	}
	while(1) {
		val = sizeof(psin);
		bzero(&psin, sizeof(psin));
		if((pfd = accept(fd, (struct sockaddr*) &psin, &val))<0) {
			perror("accept");
			return(-1);
		}
		if((pid = fork()) < 0) {
			perror("fork");
			return(-1);
		} else if(pid == 0) {	/* child */
			close(fd);
			serv_client(pfd, &psin, base_path);
			exit(0);
		}
		/* parent */
		close(pfd);
	}
}

