# VJ6-Strukture-podataka
Vjezba 6

Napisati program koji iz teksta čita riječ po riječ i radi riječnik svih riječi koje se nalaze u tekstu.
Riječnik se izrađuje na način da se u vezanu listu zapisuje samo prvo slovo riječi;
zatim se ta riječ sprema u binarno stablo na koje pokazuje pokazivač koji se nalazi u čvoru vezane liste.
Slova u vezanoj listi moraju biti sortirana. Ne smije se koristiti funkcija za sortiranje.
Ispisati sve različite riječi abecednim redoslijedom.

a) Ukoliko se u stablo zapisuje nova riječ povećaje se brojač u čvoru vezane liste.
b) Ukoliko se riječ ponavlja, potrebno je samo povećati brojač.
c) Ispisati sve različite riječi abecednim redoslijedom s brojem ponavljnja.
d) Ispisati koliko ima riječi koje započinju s početnim slovom koje se nalazi u listi.

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
