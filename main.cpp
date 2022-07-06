#include<cstdio>
#include<cstring>
#include<algorithm>
#include<vector>
#include<queue>
#include<fstream>
#include<sstream>
#include<iostream>
#include<ctime>
#include<cstdlib>
#include <stdlib.h>
#include<limits.h>
#include<math.h>
#include<iterator>
#include <string>
#include <openssl/aes.h>
#include<time.h>
#include<random>
//#include <unistd.h>
#include "aes.h"
# include <stdio.h>
#include <iomanip>
//#define NODES_NUM 4039
//#define EDGES_NUM 88234
//#define NODES_NUM 6549
//#define EDGES_NUM 112666
//#define NODES_NUM 348
//#define EDGES_NUM 557
#define NODES_NUM 4
#define EDGES_NUM 4
#define THETA 1000//约束取值范围
#define ALPHA 1//近似因子
#define PHI 158540//瞎取的一个大数
//#define WORD_NUM 5000
#define WORD_NUM 1000
//#define MAX_WORD 1//一个关键词最多出现在多少个节点中
#define MAX_WORD 100
#define N 16//位数
#define TOPK 4//topk取值范围
#define QNUM 10//查询数量
using namespace std;
ifstream infile;
//vector<string> fuzzyset[WORD_NUM];
struct Index {//keyword index structure
	vector<string> keyword;
	vector<int>node;
};
struct Word {
	vector<unsigned char*> EnWord;//关键词密文
	vector<unsigned char*> node;//包含关键词节点的加密值
};
Index KeyWordIndex[WORD_NUM];//未加密的关键词索引
Word EnWordIndex[WORD_NUM];//加密的关键词索引
double Time_HOP = 0.0;//hop索引表时间
double Time_KY = 0.0;//keyword索引表时间
double Time_ENHOP = 0.0;//hop索引加密时间
double Time_ENWORD = 0.0;//keyword索引加密时间
double Time_Gen=0.0;//生成陷门时间
double Time_Search=0.0;//搜索时间
void InitTime() {
	Time_HOP = 0.0;
	Time_KY = 0.0;
	Time_ENHOP = 0.0;
	Time_ENWORD = 0.0;
}
unsigned char K1[AES_BLOCK_SIZE + 1] = "211925f308519a4e";
unsigned char K2[AES_BLOCK_SIZE + 1] = "e0c04a8be1784e53";
unsigned char K3[AES_BLOCK_SIZE + 1] = "00000000000011a9";
unsigned char K4[AES_BLOCK_SIZE + 1] = "0230000a45dq0fcb";
double timeCost(timespec start, timespec end) {//高分辨率计时器衡量性能

	timespec temp;
	if ((end.tv_nsec - start.tv_nsec) < 0) {// tv_nsec 纳秒数
		temp.tv_sec = end.tv_sec - start.tv_sec - 1;
		temp.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
	}
	else {
		temp.tv_sec = end.tv_sec - start.tv_sec;//tv_sec 秒数
		temp.tv_nsec = end.tv_nsec - start.tv_nsec;
	}
	double ret;
	ret = (double)temp.tv_sec + (double)temp.tv_nsec / 1000000000;
	return ret;
}
struct Edge {
	int startNode;
	int endNode;
	int weight;
	int cost;
	//char keywords;	
};
vector<Edge>graph[NODES_NUM];//every vertex has a list of neighbour vertices
struct Label {//2-hop
	int self;
	int nextNode;
	unsigned long long int distance;
	unsigned long long int cost;
};
vector<Label>HopIndex[NODES_NUM];//2-hop索引
struct ENLabel {
	unsigned char* selfNode;
	unsigned char* nextNode;
	string distance;
	string cost;
};
vector<ENLabel>EnHopIndex[NODES_NUM];
string BigAdd(string num1, string num2) {
	string num;
	if (num1.size() == 0) {
		num = num2;
		return num;
	}
	if (num2.size() == 0) {
		num = num1;
		return num;
	}

	num = "";
	int n1 = num1.size() - 1, n2 = num2.size() - 1;
	int carry = 0;
	while (n1 >= 0 || n2 >= 0) {

		int a = n1 >= 0 ? num1[n1--] - '0' : 0;
		int b = n2 >= 0 ? num2[n2--] - '0' : 0;

		int t = carry + a + b;
		carry = t / 10;
		t = t % 10;
		num = to_string(t) + num;
	}
	//判断是否还有进位
	while (carry) {
		int t = carry / 10;
		carry %= 10;
		num = to_string(carry) + num;
		carry = t;
	}
	return num;
}
string OPE(unsigned long long int t, unsigned char* K) {
	long long int u;
	char r[100];
	memset(r, '\0', sizeof r);
	u = rand() % 6485324600;//瞎取的
	sprintf(r, "%lld", u);
	//cout << "r=" << r << endl;
	string rr = r;
	//cout << "rr=" << rr << endl;
	unsigned char* b;
	char p[N + 1];
	memset(p, '\0', sizeof p);
	sprintf(p, "%lld", t);
	b = (unsigned char*)p;
	//K*i
	int n1, n2;
	n1 = strlen((char*)K);
	n2 = strlen(p);
	vector<int> s;
	vector<int> y;

	y.clear();
	//unsigned char s[n1+n2];
	for (int i = 0; i < n1 + n2; i++)
		s.push_back(0);      // 每个元素赋初值0
	//memset(s, 0, n1 + n2);
	for (int i = 0; i < n1; i++)
		for (int j = 0; j < n2; j++)
			s[i + j + 1] += (K[i] - '0') * (b[j] - '0');

	for (int i = n1 + n2 - 1; i >= 0; i--)        // 进位
		if (s[i] >= 16)
		{
			s[i - 1] += s[i] / 16;
			s[i] %= 16;
		}

	int i1 = 0;
	int j1;
	while (s[i1] == 0)
		i1++;   // 跳过头部0元素
	for (j1 = 0; i1 < n1 + n2; i1++, j1++)
	{
		//cout << s[i1];
		y.push_back(s[i1]);
	}
	
	//两个大数相加
	std::stringstream ss;
	string str1;
	std::copy(y.begin(), y.end(), ostream_iterator<int>(ss, ""));
	str1 = ss.str();
	//cout<<"调用函数="<<BigAdd(str1,rr)<<endl;
	return BigAdd(str1,rr);
	/*int len1 = str1.size();
	int len2 = rr.size();
	string res = "";
	//短的字符补齐 0 
	if (len1 > len2)
		rr.insert(rr.begin(), len1 - len2, '0');
	else if (len1 < len2)
		str1.insert(str1.begin(), len2 - len1, '0');

	int cbit = 0;//进位 
	for (int i = str1.size() - 1; i >= 0; i--) {

		int sum = (str1[i] - '0') + (rr[i] - '0') + cbit;//对应位之和 + 进位 
		if (cbit)//进位清除 
			cbit--;
		res.insert(res.begin(), (sum % 10) + '0');//前插 
		if (sum / 10)//有进位 
			cbit++;
	}
	//if (cbit)
		//cout << cbit;
	cout <<"没调用="<<res<<endl;
	return res;*/
}
struct Pair {//(distance,cost) pair for Query
	unsigned long long distance;
	unsigned long long cost;
};
bool cmp(Pair u, Pair v)//用来选出所有路径中距离值最小的 α-dominate(可能不对)
{
	if ((u.cost < v.cost) && (u.distance) <= (ALPHA * (v.distance)))
	{
		return true;
	}
	else
		return false;
}
Pair Query(int v, int u, vector<Label> label[NODES_NUM]) {//for prunedDijkstrasearch
	//vector< unsigned long long int> distance;
	//vector< unsigned long long int> cost;
	Pair pair, p;
	vector<Pair> tmp;
	//printf("ok");
	if (v == u) {
		pair.distance = ULLONG_MAX;
		pair.cost = ULLONG_MAX;
		return pair;
	}
	if (!label[v].empty() && !label[u].empty()) {
		for (int i = 0; i < label[v].size(); i++) {
			for (int j = 0; j < label[u].size(); j++) {
				if (label[v][i].nextNode == label[u][j].nextNode)
				{
					p.distance = (label[v][i].distance + label[u][j].distance);
					p.cost = (label[v][i].cost + label[u][j].cost);
					tmp.push_back(p);
				}
			}
		}
		pair.distance = (*min_element(tmp.begin(), tmp.end(), cmp)).distance;
		pair.cost = (*min_element(tmp.begin(), tmp.end(), cmp)).cost;
		return pair;
	}
	else {
		pair.distance = ULLONG_MAX;
		pair.cost = ULLONG_MAX;
		return pair;
	}
}
Pair dis(int i, int j) {//求两个点之间的距离
	Pair s;
	if ((!graph[i].empty()) && (!graph[j].empty())) {
		for (int t = 0; t < graph[i].size(); t++)
		{
			//printf("endNode=%d   ", graph[i][t].endNode);
			if (graph[i][t].endNode == j)
			{
				//printf("graph[%d][%d]=%d\n", i, t, graph[i][t].weight);
				s.distance = graph[i][t].weight;
				s.cost = graph[i][t].cost;
				break;
			}
			else {
				s.distance = ULLONG_MAX;
				s.cost = ULLONG_MAX;
			}
		}
		return s;
	}
	else {
		s.distance = ULLONG_MAX;
		s.cost = ULLONG_MAX;
		return s;
	}
}
void pruned_dijkstra_search(vector<Label> label[NODES_NUM], int startNode) {//pruned BFS search for 2-hop index
	queue<int>q;//扩展结点队列
	Pair P[NODES_NUM];
	for (int i = 0; i < NODES_NUM; i++) {
		P[i].distance = ULLONG_MAX;
		P[i].cost = ULLONG_MAX;
	}
	P[startNode].distance = 0;
	P[startNode].cost = 0;//每一次循环除了startNode剩余节点的distance和cost都置为无穷

	q.push(startNode);//队列刚开始只有startNode
	while (!q.empty()) {
		int i = q.front(); //首元素出队
		q.pop();
		if (label[i].empty() || label[startNode].empty() ||
			((((Query(startNode, i, label).distance) * ALPHA) > P[i].distance)
				&& ((Query(startNode, i, label).cost) > P[i].cost))) {//从新扩展节点都节点i的路径比原索引中更好
			Label tmp;
			tmp.nextNode = startNode;
			tmp.distance = P[i].distance;
			tmp.cost = P[i].cost;
			tmp.self = i;
			label[i].push_back(tmp);//节点i加入索引		
			for (int j = 0; j < graph[i].size(); j++) {//节点i的邻居节点u
				if (P[graph[i][j].endNode].distance == ULLONG_MAX) {//节点u没被访问过
					P[graph[i][j].endNode].distance = P[i].distance + dis(i, graph[i][j].endNode).distance;
					P[graph[i][j].endNode].cost = P[i].cost + dis(i, graph[i][j].endNode).cost;
					q.push(graph[i][j].endNode);//将满足条件的节点u放进队列
				}
			}
		}
		else {
			continue;//原索引中的路径更好
		}
	}
	for (int i = 0; i < NODES_NUM; i++) {
		HopIndex[i] = label[i];//更新索引
	}
}
void Initgraph(const char* graphfile) {//for 2-hop
	freopen(graphfile, "r", stdin);//打开数据
	for (int i = 0; i < NODES_NUM; i++) {//初始化graph第一列第一个节点；graph是无向图的邻接表
		Edge tmp;
		tmp.startNode = i;
		tmp.endNode = i;
		tmp.weight = 0;
		tmp.cost = 0;
		graph[i].push_back(tmp);
	}
	for (int i = 0; i < EDGES_NUM; i++) {//将文件中的边读进graph
		int x, y;
		scanf("%d%d", &x, &y);
		Edge tmp1, tmp2;
		tmp1.startNode = x;
		//printf("x=%d\n", x);
		tmp1.endNode = y;
		//printf("y=%d\n", y);
		tmp1.cost = rand() % 100 + 1;
		tmp1.weight = rand() % 100 + 1;
		graph[x].push_back(tmp1);
		tmp2.startNode = y;
		tmp2.endNode = x;
		tmp2.cost = tmp1.cost;
		tmp2.weight = tmp1.weight;
		graph[y].push_back(tmp2);
	}
	fclose(stdin);
}
void BuildHopIndex() {//建立2-hop
	for (int i = 0; i < NODES_NUM; i++) {
		pruned_dijkstra_search(HopIndex, i);
	}
}
void EnHop() {
	//加密2-hop index
	//unsigned char digest[20];
	 unsigned char node[20];
	unsigned char nextnode[20];
	unsigned long long int distance;
	unsigned long long int cost;
	//char dis[1000];
	//char cost[1000];
	//char next[20];
	unsigned char* self;
	for (int i = 0; i < NODES_NUM; i++) {
		for (int j = 0; j < HopIndex[i].size(); j++) {
			//加密头节点
			//printf("(%d,%d)\n", i, j);
			snprintf((char*)node, sizeof(node), "%d", HopIndex[i][j].self);//头加密 int类型转化成char
			size_t len = (size_t)strlen((char*)node);
			size_t length = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;    //对齐分组
			unsigned char* iv1 = (unsigned char*)malloc(AES_BLOCK_SIZE);//块长		
			unsigned char* encrypt_result = (unsigned char*)malloc(length);
			AES_KEY en_key;
			memset((unsigned char*)iv1, 'm', AES_BLOCK_SIZE);
			memset((unsigned char*)encrypt_result, 0, length);
			AES_set_encrypt_key((const unsigned char*)K2, AES_BLOCK_SIZE * 8, &en_key);
			my_AES_cbc_encrypt(node, encrypt_result, len, &en_key, iv1);
			//cout<<"2加密="<<encrypt_result<<endl;
			ENLabel tmp;
			tmp.selfNode = encrypt_result;

			snprintf((char*)nextnode, sizeof(nextnode), "%d", HopIndex[i][j].nextNode);//头加密 int类型转化成char
			unsigned char* next_result = (unsigned char*)malloc(length);
			memset((unsigned char*)iv1, 'm', AES_BLOCK_SIZE);
			memset((unsigned char*)next_result, 0, length);
			AES_set_encrypt_key((const unsigned char*)K1, AES_BLOCK_SIZE * 8, &en_key);
			my_AES_cbc_encrypt(nextnode, next_result, len, &en_key, iv1);
			tmp.nextNode = next_result;

			distance = HopIndex[i][j].distance;
			tmp.distance = OPE(distance, K3);

			cost = HopIndex[i][j].cost;
			tmp.cost = OPE(cost * PHI, K4);

			EnHopIndex[i].push_back(tmp);

		}
	}

}
void BuildKYIndex(const char* keywordfile) {//建立关键词索引
	infile.open(keywordfile);
	char c;
	//FILE* inv;
	int num = 0;
	int t;
	char word[200];
	if (!infile) {
		cout << "The file could not be opened.\n";
	}
	char tmp = infile.get();
	while (tmp != EOF) {
		int i = 0;
		while (tmp != ' ' && tmp != EOF) {
			word[i] = tmp;
			//printf("tmp=%c\n", tmp);
			i++;
			tmp = infile.get();
		}
		word[i] = '\0';
		//printf("word=%s\n", word);
		KeyWordIndex[num].keyword.push_back(word);
		//产生fuzzyset
		string str2 = "*";
		//int num = 0;
		//for (int k = 0; k < WORD_NUM; k++) {
		for (int j = 1; j <= 2 * KeyWordIndex[num].keyword[0].size() + 1; j++) {//这一轮每个词产生多少个fuzzy词 编辑距离为1
			if ((j % 2) == 0) {
				string str3 = KeyWordIndex[num].keyword[0];
				string newword = str3.replace((j / 2) - 1, 1, str2);
				KeyWordIndex[num].keyword.push_back(newword);
			}
			else {
				string str3 = KeyWordIndex[num].keyword[0];
				string newword = str3.insert(((j + 1) / 2) - 1, str2);
				KeyWordIndex[num].keyword.push_back(newword);
			}
		}//
	//}
		int t = rand() % MAX_WORD + 1;//一个关键词在t个节点中
		for (int j = 0; j < t; j++) {
			int y = rand() % NODES_NUM;//产生这t个节点id
			vector<int>::iterator ret;
			ret = std::find(KeyWordIndex[num].node.begin(), KeyWordIndex[num].node.end(), y);//去掉产生的重复节点
			if (ret == KeyWordIndex[num].node.end())
				KeyWordIndex[num].node.push_back(y);
			else {
				continue;
			}
		}
		num++;
		tmp = infile.get();
	}
	infile.close();
}
void EnWord() {//加密关键词节点
	unsigned char* word;
	unsigned char* subkey;
	unsigned char node1[20];
	for (int i = 0; i < WORD_NUM; i++) {
		//cout<<"模糊词集个数："<<KeyWordIndex[i].keyword.size()<<endl;
		for (int j = 0; j < KeyWordIndex[i].keyword.size(); j++) {//加密关键词
			word = (unsigned char*)KeyWordIndex[i].keyword[j].c_str();
			//cout << "word=" << word << endl;
			size_t len = strlen((char*)word);
			//cout << "size11=" << len << endl;
			//printf("明文长度 AesEnc：%d\n", (int)len);
			size_t length = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;    //对齐分组
			unsigned char* iv1 = (unsigned char*)malloc(AES_BLOCK_SIZE);
			unsigned char* encrypt_result = (unsigned char*)malloc(length);
			memset((unsigned char*)iv1, 'm', AES_BLOCK_SIZE);
			memset((unsigned char*)encrypt_result, 0, length);
			AES_KEY en_key;
			AES_set_encrypt_key((const unsigned char*)K1, AES_BLOCK_SIZE * 8, &en_key);//相当于文中的伪随机置换
			my_AES_cbc_encrypt(word, encrypt_result, len, &en_key, iv1);

			EnWordIndex[i].EnWord.push_back(encrypt_result);
			//cout<<"加密结果="<<encrypt_result<<endl;
			free(iv1);
		}

		//cout<<"节点个数："<<KeyWordIndex[i].node.size()<<endl;
		for (int j = 0; j < KeyWordIndex[i].node.size(); j++) {//加密节点
			snprintf((char*)node1, sizeof(node1), "%d", KeyWordIndex[i].node[j]);//头加密 int类型转化成char
			size_t len = (size_t)strlen((char*)node1);
			//unsigned char* node = (unsigned char*)malloc(len);
			//-----
			//printf("明文长度 AesEnc：%d\n", (int)len);
			size_t length = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;    //对齐分组
			unsigned char* iv1 = (unsigned char*)malloc(AES_BLOCK_SIZE);
			unsigned char* encrypt_result = (unsigned char*)malloc(length);
			memset((unsigned char*)iv1, 'm', AES_BLOCK_SIZE);
			memset((unsigned char*)encrypt_result, 0, length);
			AES_KEY en_key;
			AES_set_encrypt_key((const unsigned char*)K2, AES_BLOCK_SIZE * 8, &en_key);
			//printf("加密密钥 AesEnc：%s\n", userkey);
			my_AES_cbc_encrypt(node1, encrypt_result, len, &en_key, iv1);
			//cout << "一轮加密结果" << encrypt_result << endl;//相当于文中的确定性加密

			size_t len2 = strlen((char*)encrypt_result);
			size_t length2 = ((len2 + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
			subkey = (unsigned char*)KeyWordIndex[i].keyword[0].c_str();
			//cout<<"加密密钥："<<subkey<<endl;
			//cout << "子密钥长度=" << strlen((char*)subkey) << endl;
			unsigned char* encrypt_result2 = (unsigned char*)malloc(length2);
			memset((unsigned char*)encrypt_result2, 0, length2);
			memset((unsigned char*)iv1, 'm', AES_BLOCK_SIZE);
			AES_KEY en_key2;
			
			AES_set_encrypt_key((const unsigned char*)subkey, AES_BLOCK_SIZE * 8, &en_key2);//二轮加密，用每个关键词的子密钥加密
			my_AES_cbc_encrypt(encrypt_result, encrypt_result2, len2, &en_key2, iv1);
			
			EnWordIndex[i].node.push_back(encrypt_result2);
			free(iv1);
		}
	}
}
struct Trap {//陷门结构
	int k;//top-k
	vector<unsigned char*>fuzzyset;//查询关键词的fuzzy集合
	unsigned char* node;//查询节点
	
	string theta2;
	string theta4;
	string theta8;
};
Trap trap[QNUM];//批量查询
void GenTrap(const char* queryfile) {//批量生成陷门 节点k以及约束值随机取
	infile.open(queryfile);
	char c;
	int num = 0;
	int t;
	char word[200];
	if (!infile) {
		cout << "The file could not be opened.\n";
	}
	char tmp = infile.get();
	while (tmp != EOF) {
		int i = 0;
		while (tmp != ' ' && tmp != EOF) {
			word[i] = tmp;
			//printf("tmp=%c\n", tmp);
			i++;
			tmp = infile.get();
		}
		word[i] = '\0';
		string keyword = word;
		vector<string>fuzzyset;
		fuzzyset.push_back(keyword);
		//cout << "查询词是" << keyword << endl;
		string str2 = "*";
		for (int j = 1; j <= 2 * keyword.size() + 1; j++) {//这一轮每个词产生多少个fuzzy词 编辑距离为1
			if ((j % 2) == 0) {
				string str3 = keyword;
				string newword = str3.replace((j / 2) - 1, 1, str2);
				//cout << "fuzzyword=" << newword << endl;
				fuzzyset.push_back(newword);
			}
			else {
				string str3 = keyword;
				string newword = str3.insert(((j + 1) / 2) - 1, str2);
				//cout << "fuzzyword=" << newword << endl;
				fuzzyset.push_back(newword);
			}
		}//
		unsigned char* wordtmp;
		//加密fuzzyset集合
		for (int i = 0; i < fuzzyset.size(); i++) {
			size_t len = fuzzyset[i].size();
			
			unsigned char* wordtmp = (unsigned char*)malloc(len);
			snprintf((char*)wordtmp, sizeof(wordtmp), "%s", fuzzyset[i].c_str());
			size_t length = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;    //对齐分组
			unsigned char* iv1 = (unsigned char*)malloc(AES_BLOCK_SIZE);
			unsigned char* encrypt_result = (unsigned char*)malloc(length);
			memset((unsigned char*)iv1, 'm', AES_BLOCK_SIZE);
			memset((unsigned char*)encrypt_result, 0, length);
			AES_KEY en_key;
			AES_set_encrypt_key((const unsigned char*)K1, AES_BLOCK_SIZE * 8, &en_key);
			//printf("加密密钥 AesEnc：%s\n", userkey);
			my_AES_cbc_encrypt(wordtmp, encrypt_result, len, &en_key, iv1);
			trap[num].fuzzyset.push_back(encrypt_result);
			//cout << "ok" << endl;
		}

		int k = rand() % TOPK + 1;//前topk节点
		int v = rand() % NODES_NUM;//查询节点
		//cout<<"查询节点是："<<v<<endl;
		int c = (rand() % THETA + THETA/2) * PHI;//不能太小
		int c2=c/2;
		int c4=c/4;
		int c8=c/8;
		//cout << "约束是" << c << endl;
		trap[num].k = k;
		
		unsigned char node[20];
		snprintf((char*)node, sizeof(node), "%d", v);//头加密 int类型转化成char
		size_t len = (size_t)strlen((char*)node);
		
		size_t length = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;    //对齐分组
		unsigned char* iv1 = (unsigned char*)malloc(AES_BLOCK_SIZE);//块长		
		unsigned char* encrypt_result = (unsigned char*)malloc(length);
		AES_KEY en_key;
		memset((unsigned char*)iv1, 'm', AES_BLOCK_SIZE);
		memset((unsigned char*)encrypt_result, 0, length);
		AES_set_encrypt_key((const unsigned char*)K2, AES_BLOCK_SIZE * 8, &en_key);
		my_AES_cbc_encrypt((unsigned char*)node, encrypt_result, len, &en_key, iv1);
		trap[num].node = encrypt_result;
		//cout << "node" << encrypt_result << endl;
		//加密cost
		//trap[num].theta = OPE(c, K4);//加密约束
		trap[num].theta2=OPE(c2,K4);
		trap[num].theta4=OPE(c4,K4);
		trap[num].theta8=OPE(c8,K4);
		//cout<<"陷门里的约束="<<trap[num].theta<<endl;
		num++;
		tmp = infile.get();

	}
	infile.close();
}
struct tr {
	unsigned char* result;
	vector<unsigned char*> node;
};
vector<tr> Search(int t) {//搜索算法
	int p = 0;//搜索出几个匹配的关键词
	vector<tr> tmpresult;
	//cout << "t=" << t << "fuzzyset长度" << trap[t].fuzzyset.size() << endl;
	for (int j = 0; j < trap[t].fuzzyset.size(); j++) {
		for (int x = 0; x < WORD_NUM; x++)
		{
			for (int y = 0; y < EnWordIndex[x].EnWord.size(); y++)
			{
				//cout << "ok" << endl;
				if (0 == strcmp((char*)EnWordIndex[x].EnWord[y], (char*)trap[t].fuzzyset[j]))
				{
					vector<unsigned char*> tmp;
					for (int m = 0; m < EnWordIndex[x].node.size(); m++)
					{
						tmp.push_back(EnWordIndex[x].node[m]);
						
					}
					tr tmp2;
					int u = 0;
					if (tmpresult.size() == 0) {
						tmp2.result = EnWordIndex[x].EnWord[0];
						//cout << "result1" << tmp2.result << endl;
						tmp2.node = tmp;
						tmpresult.push_back(tmp2);
						p++;
					}
					else {
						for (int a = 0; a < tmpresult.size(); a++) {//重复的去掉 效果完成就行写的垃圾不是问题
							if (0 == strcmp((char*)EnWordIndex[x].EnWord[0], (char*)tmpresult[a].result)) {

							}
							else { u++; }
							if (u == tmpresult.size()) {
								tmp2.result = EnWordIndex[x].EnWord[0];
								tmp2.node = tmp;
								tmpresult.push_back(tmp2);
								p++;
							}
						}
					}
				}
			}
		}
	}
	return tmpresult;
}
unsigned char* UserDec(int y, vector<tr> tmpresult) {//用户解密返回的第一个关键词
	unsigned char* decresult;
	//for (int i = 0; i < tmpresult.size(); i++) {
	AES_KEY de_key;
	size_t len = sizeof(tmpresult[y].result);
	unsigned char* word = tmpresult[y].result;
	size_t length = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	//cout << "length=" << length << endl;
	unsigned char* iv2 = (unsigned char*)malloc(AES_BLOCK_SIZE);
	unsigned char* decrypt_result = (unsigned char*)malloc(length);
	//cout << "用户解密=" << decrypt_result << endl;
	memset((unsigned char*)decrypt_result, 0, length);
	memset((unsigned char*)iv2, 'm', AES_BLOCK_SIZE);
	AES_set_decrypt_key((const unsigned char*)K1, AES_BLOCK_SIZE * 8, &de_key);
	my_AES_cbc_decrypt(word, decrypt_result, length, &de_key, iv2);
	//printf("解密结果=%s\n", decrypt_result);
	decresult = decrypt_result;
	return decresult;
	free(iv2);
}
/*unsigned char* Gensubkey(unsigned char* decresult) {//用关键词生成子密钥

	size_t len = (size_t)strlen((char*)decresult);
	unsigned char* word = (unsigned char*)malloc(len);
	word = decresult;
	size_t length = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;    //对齐分组
	unsigned char* iv1 = (unsigned char*)malloc(AES_BLOCK_SIZE);//块长
	unsigned char* encrypt_result = (unsigned char*)malloc(length);
	AES_KEY en_key;
	memset((unsigned char*)iv1, 'm', AES_BLOCK_SIZE);
	memset((unsigned char*)encrypt_result, 0, length);
	AES_set_encrypt_key((const unsigned char*)K1, AES_BLOCK_SIZE * 8, &en_key);
	my_AES_cbc_encrypt((unsigned char*)word, encrypt_result, len, &en_key, iv1);
	return encrypt_result;//返回子密钥
	free(iv1);
}*/
vector<unsigned char*> NodeDec1(int y, vector<tr> tmpresult, unsigned char* subkey) {//一轮解密节点
	vector<unsigned char*> enc;
	for (int i = 0; i < tmpresult[y].node.size(); i++) {
		unsigned char* node;
		AES_KEY de_key, de_key2;
		node = tmpresult[y].node[i];
		//cout<<"node="<<node<<endl;
		size_t len = strlen((char*)node);
		size_t length = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
		unsigned char* iv2 = (unsigned char*)malloc(AES_BLOCK_SIZE);
		unsigned char* decrypt_result = (unsigned char*)malloc(length);
		memset((unsigned char*)decrypt_result, 0, length);
		memset((unsigned char*)iv2, 'm', AES_BLOCK_SIZE);
		AES_set_decrypt_key((const unsigned char*)subkey, AES_BLOCK_SIZE * 8, &de_key);
		//cout << "子密钥=" << subkey << endl;
		//cout << "子密钥长度=" << strlen((char*)subkey) << endl;
		my_AES_cbc_decrypt(node, decrypt_result, length, &de_key, iv2);//解密二轮
		//cout<<"节点解密结果："<<decrypt_result<<endl;
		enc.push_back(decrypt_result);
	}
	return enc;
}
struct Pair2 {//(distance,cost) pair for Query
	unsigned char* node;
	string distance;
	string cost;
};

bool CmpNum(string num1,string num2) {//num1约束值是不是大于num2（两个值的和）
	int ln;
	//cout<<"1="<<num1<<endl;
	//cout<<"2="<<num2<<endl;
	if (num1.size() > num2.size())
		return true;
	else if (num1.size() == num2.size())
	{
		ln = num1.size() - 1;
		while (num1[ln] == num2[ln] && ln >= 0)
			ln--;
		if (ln >= 0 && num1[ln] > num2[ln])
			return true;
		else
			return false;
	}
	else
		return false;
}
bool Tree(string theta2, string theta4,string theta8,string str1,string str2){//约束过滤树
	int c1[3]={0,0,0};
	int c2[3]={0,0,0};
	if (CmpNum(str1,theta2))
	{
		c1[0]=1;
		if(CmpNum(str1,theta4)){
			c1[1]=1;
			if(CmpNum(str1,theta8))
				c1[2]=1;
			else{
				c1[2]=0;
			}
		}else{
			
			c1[1]=0;
		}
	}else{
		c1[0]=0;
	}
	
	if (CmpNum(str2,theta2))
	{
		c2[0]=1;
		if(CmpNum(str2,theta4)){
			c2[1]=1;
			if(CmpNum(str2,theta8))
				c2[2]=1;
			else{
				c2[2]=0;
			}
		}else{
			
			c2[1]=0;
		}
	}else{
		c2[0]=0;
	}
	//cout<<"c1="<<c1[0]<<c1[1]<<c1[2]<<endl;
	//cout<<"c2="<<c2[0]<<c2[1]<<c2[2]<<endl;
	//cout<<"比较结果"<<(4*(c1[0]+c2[0])+2*(c1[1]+c2[1])+c1[2]+c2[2])<<endl;
	if((4*(c1[0]+c2[0])+2*(c1[1]+c2[1])+c1[2]+c2[2])>=7)
		return false;
	if(!((4*(c1[0]+c2[0])+2*(c1[1]+c2[1])+c1[2]+c2[2])>5))
		return true;
	
}
bool comparison(Pair2 a, Pair2 b) {
	return CmpNum(b.distance, a.distance);
}
vector<Pair2> Search2(int i, vector<unsigned char*> enc) {//在2-hop索引中查找节点对应index,i是第几个陷门查询节点
	vector<vector<ENLabel>> tmp;//最多
	vector<ENLabel>temp;
	for (int j = 0; j < NODES_NUM; j++) {//遍历2hop index 找查询节点的2hop index
		if (0 == strcmp((char*)trap[i].node, (char*)EnHopIndex[j][0].selfNode)) {
			//cout << "hop=" << EnHopIndex[j][0].selfNode << endl;
			vector<ENLabel>temp1;
			for (int y = 0; y < EnHopIndex[j].size(); y++) {
				
				temp1.push_back(EnHopIndex[j][y]);
			}
			//cout << "ok1" << endl;
			tmp.push_back(temp1);//节点对应的索引整条取出来
		}
	}
	for (int j = 0; j < NODES_NUM; j++) {//找查询到节点的2hop index
		for (int t = 0; t < enc.size(); t++) {
			if (0 == strcmp((char*)enc[t], (char*)EnHopIndex[j][0].selfNode)) {
				//cout << "enc=" << enc[t] << endl;
				vector<ENLabel>temp2;
				for (int y = 0; y < EnHopIndex[j].size(); y++) {
					
					temp2.push_back(EnHopIndex[j][y]);
				}
				//cout << "ok2" << endl;
				tmp.push_back(temp2);
			}
		}
	}//
	//找tmp[0]和tmp[...]公共节点
	vector<Pair2> topk;
	//cout << "tmpsize=" << tmp.size() << endl;
	string min="";
	for (int t = 1; t < tmp.size(); t++) {
		vector<Pair2> p;
		Pair2 pp;	
		int e=0;
		if (!tmp[0].empty() && !tmp[t].empty()) {
			//cout << "ok3" <<endl;
			for (int y = 0; y < tmp[0].size(); y++) {
				//cout << "查询节点二跳大小="<< tmp[0].size() << endl;
				//cout<<"y="<<y<<endl;
				//int j = 0;
				for( int j=0;j < tmp[t].size();j++) {
					//cout << "其余节点二跳大小="<< tmp[t].size() << endl;
					//int yy = 0;
					//cout<<"j="<<j<<endl;
					//cout << "1=" << tmp[0][y].nextNode << endl << "2=" << tmp[t][j].nextNode << endl;
					//cout<<"比较结果="<<strcmp((char*)tmp[0][y].nextNode,(char*)tmp[t][j].nextNode)<<endl;
					if (0 == strcmp((char*)tmp[0][y].nextNode,(char*)tmp[t][j].nextNode))//公共节点
					{
						//cout << "比较结果=" << BigAdd(tmp[0][y].cost, tmp[t][j].cost)<<endl;
						//cout<<"约束值="<<trap[i].theta<<endl;
						
						if (Tree(trap[i].theta2,trap[i].theta4,trap[i].theta8,tmp[0][y].cost, tmp[t][j].cost)) {//约束过滤
							pp.distance = BigAdd(tmp[0][y].distance, tmp[t][j].distance);	
							pp.cost = BigAdd(tmp[0][y].cost, tmp[t][j].cost);
							//cout << "cost=" << BigAdd(tmp[0][y].cost, tmp[t][j].cost);
							p.push_back(pp);
						}
						//else {
						//	break;
						//}
						
					}
					else{//cout<<"else"<<endl;
					}
					
				}
			}
			//min = (*min_element(p.begin(), p.end(), cmp)).distance;
			//	pair.cost = (*min_element(tmp.begin(), tmp.end(), cmp)).cost;
			if (p.size() != 0) {
				min = p[0].distance;
				for (int y = 0; y < p.size(); y++) {

					if (CmpNum(min, p[y].distance)) {
						min = p[y].distance;
					}
				}
				//cout << "min=" << min << endl;


			}
			else {
				min = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

			}
			Pair2 gg;
			gg.node = tmp[t][0].selfNode;
			//cout << "node=" << gg.node << endl;
			gg.distance = min;
			//gg.cost = "";
			//cout << "min=" << min << endl;
			topk.push_back(gg);//查询节点和其他包含关键词节点的最短距离之和，
			//cout << "ok" << endl;
		}//
		//对topk中元素根据距离值排序
		if (topk.size() != 0)
		{
			sort(topk.begin(), topk.end(), comparison);
		}
	}
			
	return topk;
}

vector<unsigned char*>Dec(vector<Pair2> topk) {
	vector<unsigned char*> dec;
	for (int i = 0; i < topk.size(); i++) {
		AES_KEY de_key;
		size_t len = (size_t)strlen((char*)topk[i].node);
		size_t length = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
		unsigned char* iv2 = (unsigned char*)malloc(AES_BLOCK_SIZE);
		unsigned char* decrypt_result = (unsigned char*)malloc(length);
		memset((unsigned char*)decrypt_result, 0, length);
		memset((unsigned char*)iv2, 'm', AES_BLOCK_SIZE);
		AES_set_decrypt_key((const unsigned char*)K2, AES_BLOCK_SIZE * 8, &de_key);
		my_AES_cbc_decrypt(topk[i].node, decrypt_result, length, &de_key, iv2);//解密一轮
		//printf("最后解密结果=%s\n", decrypt_result);
		dec.push_back(decrypt_result);

	}
	return dec;
}
int main(int argc, char** argv) {
	timespec beginT, endT;
	const char* graphfile = "./graph/2.in";
	const char* keywordfile = "./word/1000";
	const char* queryfile = "./word/query10";
	//const char* graphfile = "./graph/0.in";
	//const char* keywordfile = "./word/keyword5000";
	Initgraph(graphfile);//初始化把图读进来
	cout<<"初始化成功！"<<endl;
	/*for (int i = 0; i < NODES_NUM; i++)//显示图
	{
		for (int j = 0; j < graph[i].size(); j++) {
			printf("graph[%d][%d]=%d      %d        %d          %d\n", i, j, graph[i][j].startNode, graph[i][j].endNode, graph[i][j].weight, graph[i][j].cost);
		}
	}*/
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &beginT);
	BuildHopIndex();//build 2-hop index
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &endT);
	Time_HOP += timeCost(beginT, endT);
	cout<<"二跳索引建立成功！"<<endl;
	//printf("build 2-hop index time is %lf\n", Time_HOP);

	/*for (int i = 0; i < NODES_NUM; i++) {//显示2-hop index
		for (int j = 0; j < HopIndex[i].size(); j++) {
			printf("2HopIndex[%d][%d]=(%d,%d,%llu,%llu)\n", i, j, HopIndex[i][j].self, HopIndex[i][j].nextNode, HopIndex[i][j].distance, HopIndex[i][j].cost);
		}
		printf("\n");
	}*/
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &beginT);
	EnHop();//加密2-hop索引
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &endT);
	Time_ENHOP += timeCost(beginT, endT);
	//printf("encrypt 2-hop index time is %lf\n", Time_ENHOP);
    cout<<"二跳索引加密成功！"<<endl;
	/*for (int i = 0; i < NODES_NUM; i++) {//显示加密2-hop index 显示不全但实际上有值
		for (int j = 0; j < EnHopIndex[i].size(); j++) {
			//printf("size=%ld\n", EnHopIndex[i].size());
			cout << "EnHopIndex[" << i << "][" << j << "=(" << EnHopIndex[i][j].selfNode << "," <<EnHopIndex[i][j].nextNode << "," << EnHopIndex[i][j].distance << "," << EnHopIndex[i][j].cost << ")" << endl;
			//printf("EnHopIndex[%d][%d]=(%s,%s,%s,%s)\n", i, j, EnHopIndex[i][j].selfNode,EnHopIndex[i][j].nextNode,EnHopIndex[i][j].distance,EnHopIndex[i][j].cost);
		}
		printf("\n");
	}*/
	
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &beginT);
	BuildKYIndex(keywordfile);//生成keyword索引
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &endT);
	Time_KY += timeCost(beginT, endT);
	//printf("build keyword index time is %lf\n", Time_KY);
	cout<<"关键词索引建立成功！"<<endl;
	/*for (int i = 0; i < WORD_NUM; i++)//显示生成的keyword索引
	{
		for (int y = 0; y < KeyWordIndex[i].keyword.size(); y++)
		{
			cout << KeyWordIndex[i].keyword[y] << endl;
		}
		for (int j = 0; j < KeyWordIndex[i].node.size(); j++)
		{
			cout << "[" << j << "]=" << KeyWordIndex[i].node[j] << endl;
		}
		cout << endl;
	}*/



	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &beginT);
	EnWord();
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &endT);
	Time_ENWORD += timeCost(beginT, endT);
	//printf("encrypt keyword index time is %lf\n", Time_ENWORD);
	cout<<"关键词索引加密成功！"<<endl;
	/*for (int i = 0; i < WORD_NUM; i++) {//显示加密keyword index 显示不全但实际上有值
		//cout << "i=" << i << endl;
		cout <<"firstword="<< EnWordIndex[i].EnWord[0] << endl;
		for (int j = 0; j < EnWordIndex[i].node.size(); j++) {
			//printf("size=%ld\n", EnHopIndex[i].size());
			cout << "EnKYIndex[" << i << "][" << j << "]=" << EnWordIndex[i].node[j] << endl;

		}
		printf("\n");
	}*/

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &beginT);
	GenTrap(queryfile);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &endT);
	Time_Gen += timeCost(beginT, endT);
//搜索
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &beginT);
	for (int i = 0; i < QNUM; i++) {
		//cout << "i=" << i << "    k=" << trap[i].k << "    v=" << trap[i].node << "    theta=" << trap[i].theta << endl;
		/*for (int j = 0; j < trap[i].fuzzyset.size(); j++)
		{
			cout << "fuzzyword=" << trap[i].fuzzyset[j] << endl;
		}*/
		cout << endl;
		vector<tr> tmpresult;
		//tmpresult.clear();
		tmpresult = Search(i);
		//显示生成的查询结果

		/*for (int j = 0; j < tmpresult.size(); j++) {
			cout << "j=" << j << endl;
			//cout << "word=" << tmpresult[j].result << endl;
			for (int p = 0; p< tmpresult[j].node.size(); p++) {
				//cout << "node=" << tmpresult[j].node[p] << endl;
			}
		}*/
		int size = tmpresult.size();
		if (size != 0) {
			//cout << "size=" << size << endl;
			for (int j = 0; j < tmpresult.size(); j++) {
				unsigned char* decresult = UserDec(j, tmpresult);
				cout << "可以选择的词是" << decresult << endl;
				//cout<<"result:"<<tmpresult[j].node[0]<<endl;
			}
			int select = rand() % tmpresult.size();//随机选择一个词作为用户要查询的关键词
			//cout << "select=" << select << endl;
			unsigned char* decresult = UserDec(select, tmpresult);
			//unsigned char* subkey = Gensubkey(decresult);//实际上关键词还要加密一下作为子密钥 但为了省事偷工减料直接将关键词作为子密钥（原理知道就行编程简单点无所谓）
			unsigned char* subkey;//不知道为啥拿decresult当密钥不对 太迷惑了
			for (int t = 0; t < WORD_NUM; t++) {
				if (0 == strcmp((char*)decresult, (char*)KeyWordIndex[t].keyword[0].c_str()))
					subkey = (unsigned char*)KeyWordIndex[t].keyword[0].c_str();

			}
			cout << "选择的词是" << subkey << endl;
			vector<unsigned char*> enc = NodeDec1(select, tmpresult, subkey);
			if (enc.size() != 0) {
				for (int j = 0; j < enc.size(); j++) {
					//cout << "enc=" << enc[j] << endl;
				}
				cout << endl;
				vector<Pair2> topk;
				topk = Search2(i, enc);
				if (topk.size() != 0) {
					//cout << "查询出来的节点是:" << endl;
					//for (int r = 0; r < trap[i].k; r++)
					//{
					//	cout << topk[r].node << endl;
					//}
					vector<unsigned char*> dec;
					dec = Dec(topk);
					cout << "最终结果" << endl;
					for (int r = 0; r < dec.size(); r++)
					{
						cout << dec[r] << endl;
					}
				}else{
					cout << "图中不含有该关键词1" << endl;
					continue; 
				}
				
			}
			else {
				cout << "图中不含有该关键词2" << endl;
				continue;
			}
	
		}
		else {
			cout << "图中不含有该关键词3" << endl;
			continue;
		}
	}
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &endT);
	Time_Search += timeCost(beginT, endT);		

	int size = 0;
	for (int i = 0; i < NODES_NUM; i++) {//加密2-hop索引大小
		size = size + EnHopIndex[i].size();
	}
	
	int EnHopsize = size * sizeof(ENLabel)>>20;//加密2-hop索引大小输出MB sizeof输出Byte
	size = 0;
	for (int i = 0; i < WORD_NUM; i++) {//加密关键词索引大小
		size=size+EnWordIndex[i].EnWord.size()+EnWordIndex[i].node.size();
	}
	int EnWordsize = size * sizeof(unsigned char)>>20;//加密关键词索引大小输出KB sizeof输出Byte
	int a=size * sizeof(unsigned char)>>10;
	//实验结果
	cout<<"二跳索引建立时间="<<Time_HOP<<endl;
	cout<<"二跳索引加密时间="<<Time_ENHOP<<endl;
	cout<<"关键词索引建立时间="<<Time_KY<<endl;
	cout<<"关键词索引加密时间="<<Time_ENWORD<<endl;
	cout<<"查询次数="<<QNUM<<endl;
	cout<<"陷门生成时间="<<Time_Gen<<endl;
	cout<<"查询时间="<<Time_Search<<endl;;
	cout<<"二跳索引大小(MB)="<<EnHopsize<<endl;
	cout<<"关键词索引大小(MB)="<<EnWordsize<<endl;
	cout<<"关键词索引大小(KB)="<<a<<endl;
	
	

	//test解密
	/*AES_KEY de_key,de_key2;
	unsigned char* first;
	first = (unsigned char*)KeyWordIndex[1].keyword[0].c_str();
	//cout << "first=" << first << endl;
	unsigned char* firstnode;
	firstnode = EnWordIndex[1].node[0];
	//cout << "node=" << firstnode << endl;
	size_t len = sizeof(firstnode);
	size_t length = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	//cout << "length=" << length << endl;
	unsigned char* iv2 = (unsigned char*)malloc(AES_BLOCK_SIZE);
	unsigned char* decrypt_result = (unsigned char*)malloc(length);
	memset((unsigned char*)decrypt_result, 0, length);
	memset((unsigned char*)iv2, 'm', AES_BLOCK_SIZE);
	AES_set_decrypt_key(first, AES_BLOCK_SIZE * 8, &de_key);
	//cout << "密钥=" << first << endl;
	my_AES_cbc_decrypt(firstnode, decrypt_result, length, &de_key, iv2);//解密二轮
	printf("二轮解密结果=%s\n", decrypt_result);

	size_t len2 = (size_t)strlen((char*)decrypt_result);
	size_t length2 = ((len2 + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	unsigned char* decrypt_result2 = (unsigned char*)malloc(length2);
	memset((unsigned char*)decrypt_result2, 0, length2);
	memset((unsigned char*)iv2, 'm', AES_BLOCK_SIZE);
	AES_set_decrypt_key((const unsigned char*)K2, AES_BLOCK_SIZE * 8, &de_key2);
	my_AES_cbc_decrypt(decrypt_result , decrypt_result2, length2, &de_key2, iv2);//解密一轮
	printf("最后解密结果=%s\n", decrypt_result2);

	free(iv2);
	free(decrypt_result);
	free(decrypt_result2);*/
	return(0); 
}