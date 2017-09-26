/*
Zadatak 1. - Grupa 1.
-----------------------------------------------------------------------------------------------------------
Napisati program koji iz teksta èita rijeè po rijeè i radi rijeènik svih rijeèi koje se nalaze u tekstu.
Rijeènik se izraðuje na naèin da se u vezanu listu zapisuje samo prvo slovo rijeèi;
zatim se ta rijeè sprema u binarno stablo na koje pokazuje pokazivaè koji se nalazi u èvoru vezane liste.
Slova u vezanoj listi moraju biti sortirana. Ne smije se koristiti funkcija za sortiranje.
Ispisati sve razlièite rijeèi abecednim redoslijedom.

a) Ukoliko se u stablo zapisuje nova rijeè poveæaje se brojaè u èvoru vezane liste.
b) Ukoliko se rijeè ponavlja, potrebno je samo poveæati brojaè.
c) Ispisati sve razlièite rijeèi abecednim redoslijedom s brojem ponavljnja.
d) Ispisati koliko ima rijeèi koje zapoèinju s poèetnim slovom koje se nalazi u listi.

Napomena:
typedef struct _listNode
{
char firstLetter;
int wordsCounter;
struct _treeNode *myRoot;
struct _listNode *Next;
}_LISTNODE;

typedef struct _treeNode
{
char[50] word;
int wordCounter;
struct _treeNode *Left;
struct _treeNode *Right;
}_TREENODE;
__________________________________________________________________________________________________________
*/

#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <time.h>
#include <string.h>

typedef struct stablo *node;
typedef struct stablo
{
	char word[50];//rijeci koje cuvamo
	int wordCounter;//broj koliko se puta ista rijec ponovila
	node left;
	node right;
}stablo;

typedef struct lista *pos;
typedef struct lista
{
	char firstLetter;//prvo slovo
	int wordsCounter;//broj rijeci koje su pocele sa tim prvim slovom
	node myRoot;
	pos next;
}lista;

void citanjeIzDatoteke(pos);//funkcija koja cita iz datoteke, iz nje se pozivaju sve funkcije za upisivanje u listu i stabla
//void ispisListe(Pos);//funkcija koja je samo sluzila za testiranje i provjeru
char toLower(char);//funkcija koja velika slova prebacuje u mala
node unosUStablo(char[], node);//funkcija koja rijec unosi u stablo
void printListu(pos);//funkcija koja ispisuje sve sto zadatak trazi, u njoj se poziva funkcija za ispis stabla
void printInorderStablo(node);//generic inline ispis stabla

int main()
{
	lista head;
	head.next = NULL;

	citanjeIzDatoteke(&head);//glavni dio koda, odi se skoro sve dogadja
	//ispisListe(&head);
	printListu(&head);

	printf("\n");

	return 0;
}

void citanjeIzDatoteke(pos P)//ova funkcija cita iz datoteke i zapisuje u listu, u njoj se poziva funkcija za zapis u stablo
{
	pos R, N;//R sluzi za pamcenje "head"a liste
	char lowercase;//char koji ce nam sluziti za prebacivanje velikih slova u mala
	R = P;//R postaje head (prvi clan) liste
	FILE *dat;
	dat = fopen("Text.txt", "r");
	char rijec[50];
	while (!feof(dat))//petlja se vrti dok se ne dodje do kraja filea
	{
		pos temp = (pos)malloc(sizeof(lista));//dinamicka alokacija
		fscanf(dat, " %s", rijec);//ode citamo rijec po rijec
		lowercase = rijec[0];//uzimamo prvo slovo rijeci
		lowercase = toLower(lowercase);//u slucaju da je veliko prebacujemo ga u malo (mogli smo i mala u veliko, svejedno je) tako da sva budu ista radi abecede odnosno usporeðivanja koje je prije u ASCII tablici
		if (NULL == P->next)//ovo ce se izvrsiti samo prvi put kada se pozove
		{
			temp->myRoot = NULL;
			temp->firstLetter = lowercase;
			temp->wordsCounter = 1;//brojac rijeci postavljamo na 1
			temp->myRoot = unosUStablo(rijec, temp->myRoot);//pozivamo funkciju koja ce ubacit rijec u stablo ako je potrebno, a ako je vec u stablu povecat ce brojac za 1
			temp->next = P->next;
			P->next = temp;
		}
		//OVO SVE SA UNOSENJEM PRVOG SLOVA PA ONDA ULASKA U PETLJU RADIMO ZATO DA U PETLJI ODMA MOZEMO POCETI USPOREDJIVATI SLOVA, TAKO DA JEDNO VEC MORA BITI UNESENO
		else
		{
			P = R;//P vracamo na pocetak
			N = R->next;//N je od sada P->next
			while (lowercase > N->firstLetter && NULL != N->next)//moramo ih odma upisati u abecednom redosljedu, tako da dok je god slovo po abecedi iza trenutnog slova (u elementu u kojem se nalazimo) idemo dalje
			{													//kroz listu dok ne doðemo do slova koje je isto nasem slovu ili iza naseg u abecedi
				P = P->next;
				N = N->next;
			}
			if (lowercase == N->firstLetter)//u slucaju da je to slovo isto kao i u vec postojecem elementu u listi 
			{
				N->wordsCounter++;//samo dizemo brojac
				N->myRoot = unosUStablo(rijec, N->myRoot);//ubacujemo rijec u stablo ili dizemo brojac na toj rijeci
			}
			else//isti ka i unos prvog slova, samo sta ode ne unosimo striktno na prvo mjesto nego na ono koje je abeceda odredila
			{
				temp->myRoot = NULL;
				temp->firstLetter = lowercase;
				temp->wordsCounter = 1;
				temp->myRoot = unosUStablo(rijec, temp->myRoot);
				temp->next = P->next;
				P->next = temp;
			}
		}//PROBLEM JE STA KAKO SMO PRVO SLOVO UNJELI IZVAN PETLJE ONO OSTANE UVIJEK NA ZANJEM MJESTU, TAKO DA TO TREBAMO POPRAVITI STA CEMO GA PONOVO UNJETI, A ZADNJE MJESTO IZBRISATI
	}
	rewind(dat);//VAZNO, ovako se ponovno vracamo na pocetak filea, inace da nismo korisitili rewind bi ponovno procitali zadnju rijec
	fscanf(dat, " %s", rijec);//citamo ponovo prvu rijec
	pos temp = (pos)malloc(sizeof(struct lista));
	P = R;//ponovo P postavljamo na pocetak
	N = R->next;//N postaje prvi element koji ima slovo u sebi
	while (NULL != P->next)//P vodimo do zadnjeg elementa da bi postao elemnt koji u sebi sadrzi slovo koje nije na pravom mijestu
	{
		P = P->next;
	}
	while (P->firstLetter > N->firstLetter && NULL != N->next)//kao i gore u petlji usporedjujemo zadnje slovo sa svim ostalima da ga mozemo ponovno ubaciti u listu, samo ovaj put na pravo mjesto
	{
		N = N->next;
	}
	while (R->next != N)//s obzirom da nam ne treba vise R (koji je do sada sluzija ka pocetak liste) sada ga mozemo dovesti do prednog od N
	{
		R = R->next;
	}
	if (P->firstLetter == N->firstLetter)//ako vec imamo to slovo u listi, povecajemo brojac i rijec ubacujemo u stablo
	{
		N->wordsCounter++;
		N->myRoot = unosUStablo(rijec, N->myRoot);
	}
	else//ako nemamo onda ga ubacujemo u mjesto odreðeno abecedom, R je ispred N (N je prvo vece slovo od naseg), u P je sacuvano nase slovo
	{
		temp->myRoot = NULL;
		temp->firstLetter = P->firstLetter;
		temp->wordsCounter = 1;
		temp->myRoot = unosUStablo(rijec, temp->myRoot);
		temp->next = R->next;
		R->next = temp;
	}
	while (R->next != P)//R mozemo dovesti do predzadnjeg mjesta da izbrisemo zadnje
	{
		R = R->next;
	}
	R->next = NULL;//predzadnje mjesto odvajamo od zadnjeg
	free(P);//oslobaðamo memoriju zadnjeg mjesta
	fclose(dat);//zatvaramo datoteku
}

/*void ispisListe(pos P)//samo sluzi za testove i provjere
{
	P = P->next;
	while (NULL != P)
	{
		printf("\n\t%c %d", P->firstLetter, P->wordsCounter);
		P = P->next;
	}
}*/

char toLower(char ch)
{
	if (ch >= 'A' && ch <= 'Z')
	{
		ch = ch + 32;
	}
	return ch;
}

node unosUStablo(char rijec[], node S)//dovodimo rijec i temp->myroot
{
	if (NULL == S || strcmp(S->word, rijec) == 0)//provjeravamo je li prazno ili ako ima rjec, je li to ista ka i nova
	{
		if (NULL == S)//strcmp(S->word, rijec) == 0)//u pocetku sam kao uvijet koristija ovaj zakomentirani dio (naravno zamjenjen sadrzaj od if i else), ali to nikako nije tilo radit pa sam mora ovako
		{											//ako je ovaj node prazan u njega normalno unosim
			S = (node)malloc(sizeof(stablo));
			S->left = NULL;
			S->right = NULL;
			strcpy(S->word, rijec);
			S->wordCounter = 1;
		}
		else//ako node nije prazan to znaci da je u njemu ista rijec kao i nova (radi prog uvijeta u funkciji) pa onda samo word counter povecavam
		{
			S->wordCounter++;
		}
	}
	else if(strcmpi(S->word, rijec) < 0)//standardna rekurzija
	{
		S->right = unosUStablo(rijec, S->right);
	}
	else if (strcmpi(S->word, rijec) > 0)
	{
		S->left = unosUStablo(rijec, S->left);
	}
	return S;
}

void printListu(pos P)//printa sve sto nam treba
{
	P = P->next;
	printf("\nSLOVO\tBROJ RAZLICITIH RIJECI");
	while (NULL != P)
	{
		printf("\n%c\t%d", P->firstLetter, P->wordsCounter);
		printInorderStablo(P->myRoot);//nakon svakog slova i broja koliko se puta ponovilo, printamo stablo sa svim informacijama
		P = P->next;
	}
}

void printInorderStablo(node S)//generic inorder printanje stabla (tako ce sve po abecedi ispast)
{
	if (NULL != S)
	{
		printInorderStablo(S->left);
		printf("\n\t\t%s\t%d", S->word, S->wordCounter);
		printInorderStablo(S->right);
	}
}//NEKE RIJECI U SEBI SADRZE , ILI ., TO MI SE NIJE DALO MICAT IAKO NIJE TESKO