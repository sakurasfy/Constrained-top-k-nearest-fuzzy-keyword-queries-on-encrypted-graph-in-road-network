#ifndef INDEX_H
#define INDEX_H
#include<iostream>
#include<fstream>
#include<string>
#include<cstring>
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
#include<limits.h>
#include<math.h>

//#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <openssl/aes.h>
#include<time.h>
#include<random>
#define WORD_NUM 5000
#define NODES_NUM 3000
#define MAX_WORD 450
using namespace std;  
struct Index {
	vector<string> keyword;
	vector<int>node;
};
Index KeyWordIndex[WORD_NUM];
struct Edge {
	int startNode;
	int endNode;
	int weight;
	int cost;
	//char keywords;	
};
vector<Edge>graph[NODES_NUM];//every vertex has a list of neighbour vertices
struct Label {
	int nextNode;
	unsigned long long int distance;
	unsigned long long int cost;
};
vector<Label>HopIndex[NODES_NUM];//2-hop索引
struct Pair {//(distance,cost) pair for Query
	unsigned long long distance;
	unsigned long long cost;
};
bool cmp(Pair u, Pair v);
Pair Query(int v, int u, vector<Label> label[NODES_NUM]);
Pair dis(int i, int j);
void pruned_dijkstra_search(vector<Label> label[NODES_NUM], int startNode);
void Initgraph(const char* graphfile);
void BuildHopIndex();
void BuildKYIndex(const char* keywordfile);
#endif