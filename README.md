# Encryptee – Simple Encryption/Decryption Demo (C#)

Encryptee je konzolová aplikace v jazyce C#, která demonstruje použití tří klasických návrhových vzorů (Strategy, Observer a Decorator) v kombinaci s jednoduchými implementacemi šifrování. Projekt má vzdělávací charakter a slouží k pochopení strukturovaného návrhu aplikace a oddělení odpovědností v kódu.

Aplikace umožňuje šifrovat a dešifrovat text pomocí tří algoritmů: Caesarovy šifry, XOR šifry a AES-PBKDF2. Součástí programu je také modulární logger, který lze skládat pomocí dekorátorů a rozšiřovat bez zásahů do původního kódu.

---

## Hlavní vlastnosti

- Šifrování a dešifrování textu
- Výběr šifrovacího algoritmu z příkazové řádky
- Caesar, XOR a AES-PBKDF2 strategie
- Přehledné logování událostí (start, dokončení, chyba)
- Rozšiřitelný logger pomocí Decorator patternu
- Log výstupu může být v čistém textu nebo formátu JSON
- Bezpečná varianta s AES (CBC, PKCS7) a derivací klíče pomocí PBKDF2
- Náhodná sůl a IV pro každý šifrovací běh
- Výstup u binárních dat vždy v Base64

---

## Použité návrhové vzory

### Strategy
Každý šifrovací algoritmus implementuje společné rozhraní `IEncryptStrategy`.  
To umožňuje jednoduše přidat nový algoritmus bez úprav ve třídě engine. Výběr strategie probíhá v `Program.cs` podle volby uživatele.

### Observer
Engine neprovádí přímé výpisy na konzoli. Místo toho generuje události:
- `OnStart`
- `OnComplete`
- `OnError`

O zobrazení nebo záznam událostí se stará třída implementující `ICryptoObserver`. Díky tomu je možné jednoduše měnit způsob logování (například přepnout z konzole na soubor).

### Decorator
Logger je navržen jako skládací struktura.  
Základní `ConsoleLogger` lze obalit dekorátory, které přidávají nové chování:

- `TimestampDecorator` přidává časové razítko
- `JsonDecorator` převádí zprávy do JSON formátu

Výhodou je, že není potřeba upravovat původní logger, stačí vytvářet další dekorátory.

---

## Implementované šifrovací strategie

### 1. Caesar Strategy
Jednoduchý didaktický algoritmus pracující pouze s ASCII písmeny (A–Z, a–z).  
Posouvá znaky o definovaný počet pozic. Ostatní znaky zůstávají beze změny.

### 2. XOR Strategy
Pracuje s bajty. Vstupní text je převeden na UTF8 a následně XORován cyklickým klíčem.  
Výstup je uložen v Base64. Tato strategie je pouze demonstrační.

### 3. AES-PBKDF2 Strategy
Bezpečnější varianta používající:

- AES v režimu CBC
- PKCS7 padding
- 256bit klíč
- PBKDF2 (Rfc2898DeriveBytes) se 100 000 iteracemi
- Náhodnou 16B sůl
- Náhodný 16B IV

## Spuštění aplikace

Projekt lze spustit pomocí příkazu: dotnet run


Program následně vyzve uživatele k:

1. Výběru režimu (`enc` nebo `dec`)
2. Volbě algoritmu (`1`, `2`, `3`)
3. Zadání textu
4. Zadání hesla/klíče (u AES a XOR)

Výstup je u šifrování vždy v Base64, u dešifrování v UTF-8.

---

## Účel projektu

Projekt je určen pro studium:

- návrhových vzorů (Strategy, Observer, Decorator),
- práce s kryptografií v jazyce C#,
- vytváření modulární a rozšiřitelné architektury,
- dělení odpovědností mezi třídy,
- konstrukce šifrovacích nástrojů pro výukové účely.

Kód je psán s důrazem na přehlednost a snadnou rozšiřitelnost.

---

## Rozšíření

Možnosti dalšího rozvoje:

- přidání dalších šifrovacích strategií,
- logování do souboru pomocí nového dekorátoru,
- automatické testy pro jednotlivé strategie,
- přidání GUI vrstvy,
- generování klíčů nebo náhodných hesel.

---
