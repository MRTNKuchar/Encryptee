using System;                     // Základní typy a konzolové I/O (Console, DateTime, Exception, atd.)
using System.IO;                  // I/O proudy a soubory (tady není zásadně využité, ale nevadí)
using System.Linq;                // LINQ rozšíření (Select, Sum, Take, Skip, ToArray, atd.)
using System.Security.Cryptography; // Kryptografické algoritmy (AES, PBKDF2/Rfc2898DeriveBytes, RNG)
using System.Text;                // Práce s textem a kódování (Encoding.UTF8)
using System.Text.Json;           // Serializace/deserializace JSON (pro JSON logger)

// =======================================================
// Encryptee – jednoduchý šifrátor/dešifrátor (Strategy+Observer+Decorator)
//
// Použité návrhové vzory:
// 1) Strategy  -> možnost volby algoritmu šifrování (Caesar / XOR / AES-PBKDF2)
// 2) Observer  -> engine ohlašuje události (Start/Complete/Error), UI/logování je oddělené
// 3) Decorator -> skládání loggeru do řetězce: Timestamp -> Json -> Console
//
// Motivace:
// - Strategy: Chceme měnit algoritmus bez úprav orchestrátoru (engine).
// - Observer: Chceme oddělit "co se děje" od "jak se to zobrazuje/loguje".
// - Decorator: Chceme logování rozšiřovat (přidávat čas, JSON) bez úprav základního loggeru.
// =======================================================

#region Logger (Decorator)
// ================================
// LOGGER (DECORATOR PATTERN)
// ================================
// Cíl: Mít jednoduché rozhraní ILogger a skládáním přes dekorátory přidávat funkce jako timestamp,
//      formátování do JSON, zapis do konzole, souboru apod. – bez zásahu do původního ConsoleLogger.

// Minimální logger – dává smysl jako "jádro" řetězce dekorátorů.
public interface ILogger
{
    // Metoda pro zalogování jedné řádky textu.
    void Log(string line);
}

// Konkrétní logger, který prostě vypisuje řádky na konzoli.
// "sealed" = třídu už nejde dědit (není třeba ji rozšiřovat dědičností,
// dekorátory to vyřeší lépe).
public sealed class ConsoleLogger : ILogger
{
    public void Log(string line) => Console.WriteLine(line);
}

// Abstraktní základ pro dekorátory: sám implementuje ILogger,
// ale uvnitř drží "vnořený" logger, na který to deleguje.
// Důležité: díky tomu lze skládat libovolně dlouhý řetězec dekorátorů.
public abstract class LoggerDecorator : ILogger
{
    // Vnitřní logger, na který budeme delegovat.
    protected readonly ILogger Inner;

    // Konstruktor dostane logger (např. ConsoleLogger nebo jiný dekorátor).
    protected LoggerDecorator(ILogger inner) => Inner = inner;

    // Virtuální Log – výchozí chování je delegovat dál beze změny.
    // Potomci (konkrétní dekorátory) si to mohou přetížit a přidat něco před/po.
    public virtual void Log(string line) => Inner.Log(line);
}

// Dekorátor, který přidává časové razítko (timestamp) na začátek zprávy.
// Ukázka jednoduchého "předzpracování" zprávy a pak volání base.Log (tj. delegace dál).
public sealed class TimestampDecorator : LoggerDecorator
{
    public TimestampDecorator(ILogger inner) : base(inner) { }

    public override void Log(string line) =>
        // Přidáme timestamp "YYYY-MM-DD HH:MM:SS.mmm | původní zpráva"
        base.Log($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} | {line}");
}

// Dekorátor, který formátuje log do JSON (užitečné pro audit nebo ingest do SIEM).
// Zprávu "obalí" do objektu { ts, level, source, message } a až pak ji pošle dál.
public sealed class JsonDecorator : LoggerDecorator
{
    private readonly string _source; // Název zdroje (aplikace/modulu)
    private readonly string _level;  // Úroveň logu (INFO/WARN/ERROR...)

    public JsonDecorator(ILogger inner, string source = "encryptee", string level = "INFO") : base(inner)
    {
        _source = source;
        _level = level;
    }

    public override void Log(string line)
    {
        // Payload s UTC časem kvůli konzistentnímu logování napříč časovými pásmy.
        var payload = new
        {
            ts = DateTime.UtcNow,
            level = _level,
            source = _source,
            message = line
        };

        // Serializace do JSON a delegace dál (např. TimestampDecorator -> ConsoleLogger).
        base.Log(JsonSerializer.Serialize(payload));
    }
}
#endregion

#region Observer (události šifrování)
// ================================
// OBSERVER PATTERN (UDÁLOSTI)
// ================================
// Cíl: Engine generuje události (start, komplet, chyba), ale neřeší, jak a kam se mají zobrazit.
//      To přebírá "pozorovatel" (observer), který si může logovat po svém (přes ILogger pipeline).

// Rozhraní pro pozorovatele šifrování.
// Engine volá tyto metody v daných momentech.
public interface ICryptoObserver
{
    void OnStart(string mode, string algo);                            // Zahájení operace
    void OnComplete(string outputPreviewBase64, TimeSpan elapsed);     // Dokončení operace
    void OnError(string reason);                                       // Chyba v průběhu
}

// Jednoduchý observer, který posílá zprávy do loggeru.
// Logger může být obyč. konzole, nebo řetězec decorátorů (JSON+timestamp).
public sealed class ConsoleCryptoObserver : ICryptoObserver
{
    private readonly ILogger _log;

    // Injekce loggeru – díky tomu si zvenku určíme, jak se bude logovat (textově/JSON/čas).
    public ConsoleCryptoObserver(ILogger log) => _log = log;

    public void OnStart(string mode, string algo)
        => _log.Log($"START | mode={mode} | algo={algo}");

    public void OnComplete(string outputPreviewBase64, TimeSpan elapsed)
        => _log.Log($"DONE  | elapsed={elapsed} | preview(base64)={outputPreviewBase64}");

    public void OnError(string reason)
        => _log.Log($"ERROR | {reason}");
}
#endregion

#region Strategy (šifrovací strategie)
// ================================
// STRATEGY PATTERN (ALGORITMY)
// ================================
// Cíl: Umožnit volit algoritmus za běhu (runtime), aniž by Engine musel znát jeho detaily.
//      Každá strategie nabídne stejné rozhraní Process(...).

// Společné rozhraní: vstup i výstup jsou stringy (kvůli konzoli).
// Pozor: u binárních výstupů používáme Base64 (aby šlo poslat/ukázat v textové podobě).
public interface IEncryptStrategy
{
    // "mode" = "enc" (encrypt) nebo "dec" (decrypt).
    // "passwordOrKey" může být ignorováno (např. u Caesar strategie).
    string Process(string input, string passwordOrKey, string mode);
}

// ----------------------
// 1) Caesar (didakticky)
// ----------------------
// Posouvá jen ASCII písmena A-Z a a-z o daný posun "shift" (diakritiku neřešíme).
public sealed class CaesarStrategy : IEncryptStrategy
{
    private readonly int _shift; // Normalizovaný posun 0..25

    public CaesarStrategy(int shift)
        // Normalizace posunu do intervalu 0..25, zvládne i negativní/velké posuny.
        => _shift = ((shift % 26) + 26) % 26;

    public string Process(string input, string key, string mode)
    {
        // Pokud dešifrujeme, použijeme záporný posun.
        int s = _shift * (mode == "dec" ? -1 : 1);

        // Pro každý znak aplikujeme funkci Shift(...) a složíme nový string.
        return new string(input.Select(Shift).ToArray());

        // Vnořená funkce (lokální), která posune jednotlivý znak, pokud je písmeno.
        char Shift(char c)
        {
            if (c >= 'a' && c <= 'z') return (char)('a' + (c - 'a' + s + 26) % 26);
            if (c >= 'A' && c <= 'Z') return (char)('A' + (c - 'A' + s + 26) % 26);
            return c; // Ne-písmena ponecháme beze změny (mezery, čísla, diakritika...)
        }
    }
}

// ----------------------
// 2) XOR (didakticky)
// ----------------------
// Jednoduchý příklad práce s bajty.
// Šifrování: text -> UTF8 byty -> XOR s klíčem (cyklicky) -> Base64.
// Dešifrování: Base64 -> XOR s klíčem -> UTF8 text.
// Bezpečnostně nevhodné pro praxi, je to demonstrace.
public sealed class XorStrategy : IEncryptStrategy
{
    public string Process(string input, string key, string mode)
    {
        // Bez klíče to nedává smysl (XOR potřebuje "tajemství").
        if (string.IsNullOrEmpty(key)) throw new ArgumentException("Key cannot be empty.");

        if (mode == "enc")
        {
            // Z textu uděláme bajty.
            var data = Encoding.UTF8.GetBytes(input);
            // Z klíče uděláme bajty (stejné kódování).
            var res = Xor(data, Encoding.UTF8.GetBytes(key));
            // Výsledek (bajty) zabalíme do Base64, aby se dal zobrazit/poslat jako string.
            return Convert.ToBase64String(res);
        }
        else if (mode == "dec")
        {
            // V opačném směru: Base64 -> bajty
            var data = Convert.FromBase64String(input);
            // XOR s bajty klíče
            var res = Xor(data, Encoding.UTF8.GetBytes(key));
            // Rozbalíme do UTF-8 textu.
            return Encoding.UTF8.GetString(res);
        }
        else throw new ArgumentException("mode must be 'enc' or 'dec'");
    }

    // Pomocná metoda: aplikuje XOR cyklicky klíčem přes celé data pole.
    private static byte[] Xor(byte[] data, byte[] key)
    {
        var res = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            res[i] = (byte)(data[i] ^ key[i % key.Length]); // i % key.Length = cyklení klíče
        return res;
    }
}

// ----------------------
// 3) AES + PBKDF2 (bezpečnější varianta)
// ----------------------
// AES v režimu CBC s PKCS7 paddingem.
// Klíč je odvozen z hesla pomocí PBKDF2 (Rfc2898DeriveBytes) se solí.
// Výstupní formát: Base64( salt[16] | iv[16] | ciphertext[...] )
public sealed class AesPbkdf2Strategy : IEncryptStrategy
{
    // Parametry kryptografie:
    private const int SaltSize = 16;       // 128-bit sůl pro PBKDF2
    private const int IvSize = 16;         // 128-bit blok pro AES (IV stejná velikost)
    private const int KeySizeBytes = 32;   // 256-bit klíč (32 bajtů)
    private const int Iterations = 100_000; // Počet iterací PBKDF2 (zvyšuje výpočetní náročnost pro útočníka)

    public string Process(string input, string password, string mode)
    {
        // Bez hesla nemůžeme odvodit klíč.
        if (string.IsNullOrEmpty(password)) throw new ArgumentException("Password cannot be empty.");

        if (mode == "enc")
        {
            // 1) Vygenerujeme náhodnou sůl (salt) – není tajná, ale musí být náhodná pro každý šifrovací běh.
            var salt = RandomBytes(SaltSize);

            // 2) Z hesla + soli odvodíme klíč pomocí PBKDF2 (Rfc2898DeriveBytes).
            using var keyDerive = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
            var key = keyDerive.GetBytes(KeySizeBytes); // 256-bit klíč

            // 3) Připravíme AES v režimu CBC s PKCS7 paddingem.
            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.GenerateIV(); // náhodný IV, unikátní pro každý šifrovací běh

            // 4) Šifrování
            using var enc = aes.CreateEncryptor();
            var plaintext = Encoding.UTF8.GetBytes(input); // text -> bajty
            var cipher = enc.TransformFinalBlock(plaintext, 0, plaintext.Length);

            // 5) Složíme blob: [salt | IV | ciphertext] a zabalíme do Base64 pro přenos/uložení.
            var blob = Combine(salt, aes.IV, cipher);
            return Convert.ToBase64String(blob);
        }
        else if (mode == "dec")
        {
            // 1) Převedeme Base64 string zpět na bajty (blob)
            var blob = Convert.FromBase64String(input);

            // Rychlá kontrola minimální délky (aspoň salt+iv+1 byte ciphertextu).
            if (blob.Length < SaltSize + IvSize + 1) throw new ArgumentException("Invalid AES blob.");

            // 2) Rozřežeme: [salt(16) | iv(16) | cipher(zbytek)]
            var salt = blob.Take(SaltSize).ToArray();
            var iv = blob.Skip(SaltSize).Take(IvSize).ToArray();
            var cipher = blob.Skip(SaltSize + IvSize).ToArray();

            // 3) Z hesla + soli znovu odvodíme stejný klíč.
            using var keyDerive = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
            var key = keyDerive.GetBytes(KeySizeBytes);

            // 4) Nastavíme AES pro dešifrování.
            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.IV = iv;

            // 5) Dešifrujeme ciphertext a vrátíme UTF-8 text.
            using var dec = aes.CreateDecryptor();
            var plain = dec.TransformFinalBlock(cipher, 0, cipher.Length);
            return Encoding.UTF8.GetString(plain);
        }
        else throw new ArgumentException("mode must be 'enc' or 'dec'");
    }

    // Vygeneruje "n" kryptograficky kvalitních náhodných bajtů.
    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        RandomNumberGenerator.Fill(b); // statická metoda .NET – používá kryptograficky bezpečný RNG
        return b;
    }

    // Spojí více byte[] polí do jednoho (efektivněji než postupným přidáváním).
    private static byte[] Combine(params byte[][] arrays)
    {
        var len = arrays.Sum(a => a.Length);   // Celková délka výsledku
        var res = new byte[len];
        int pos = 0;
        foreach (var a in arrays)
        {
            Buffer.BlockCopy(a, 0, res, pos, a.Length); // Rychlá kopie bloků paměti
            pos += a.Length;
        }
        return res;
    }
}
#endregion

#region Engine (orchestruje strategii + observer + logger)
// ================================
// ENGINE (ORCHESTRÁTOR BĚHU)
// ================================
// Cíl: Neřešit detaily algoritmu ani logování. Jen:
// - nahlásit začátek,
// - zavolat strategii,
// - nahlásit dokončení (čas + náhled),
// - vypsat výsledek uživateli,
// - nahlásit případnou chybu.

// Engine je jednoduchá třída orientovaná na jednu operaci (encrypt/decrypt).
public sealed class EncrypteeEngine
{
    private readonly IEncryptStrategy _strategy;  // Zvolená šifra (Strategy)
    private readonly ICryptoObserver _observer;   // Pozorovatel událostí (Observer)

    // Kompozice: "injekčně" dostaneme strategii a observer – engine se nemusí vázat na konkrétní implementace.
    public EncrypteeEngine(IEncryptStrategy strategy, ICryptoObserver observer)
    {
        _strategy = strategy;
        _observer = observer;
    }

    // Spustí jednu operaci s daným režimem, vstupem a klíčem/heslem.
    public void Run(string mode, string input, string passwordOrKey)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew(); // měření času operace
        try
        {
            // 1) Ohlásíme start (pozorovateli řekneme mode + název třídy strategie)
            _observer.OnStart(mode, _strategy.GetType().Name);

            // 2) Provedeme šifru/dešifru (jediný bod, kde "saháme" na strategii)
            var output = _strategy.Process(input, passwordOrKey, mode);

            // 3) Připravíme náhled (preview) do logu:
            //    - při "enc": výstup XOR/AES už je Base64, u Caesar je text (může zůstat)
            //    - při "dec": konvertujeme čistý text do Base64 (aby byl přenositelný/logovatelný)
            var preview = mode == "enc"
                ? output // už je base64 pro XOR/AES; u Caesar je text - nevadí, je to jen preview
                : Convert.ToBase64String(Encoding.UTF8.GetBytes(output));

            sw.Stop(); // zastavíme stopky
            _observer.OnComplete(preview, sw.Elapsed); // 4) Ohlásíme dokončení (preview + čas)

            // 5) Užitečný výstup pro uživatele do konzole (mimo logy)
            if (mode == "enc")
            {
                Console.WriteLine("\n=== ENCRYPTED (base64) ===");
                Console.WriteLine(output); // Base64 u XOR/AES, text u Caesar
            }
            else
            {
                Console.WriteLine("\n=== DECRYPTED (utf8) ===");
                Console.WriteLine(output); // Dešifrovaný text
            }
        }
        catch (Exception ex)
        {
            // V případě chyby zastavíme měření a ohlásíme error.
            sw.Stop();
            _observer.OnError(ex.Message);
        }
    }
}
#endregion

#region Demo (Main)
// ================================
// DEMO (HLAVNÍ PROGRAM)
// ================================
// Cíl: Interaktivně načíst volby uživatele, složit logger pipeline, vytvořit observer a strategii
//      a předat je do engine. Následně spustit jednu operaci.

public static class Program
{
    public static void Main()
    {
        // Nastaví UTF-8 pro výstup (kvůli češtině, emoji apod.)
        Console.OutputEncoding = Encoding.UTF8;

        // ----- Logger pipeline (Decorator) -----
        // Dvě možné varianty:
        // 1) čitelný text s časem:
        // ILogger log = new TimestampDecorator(new ConsoleLogger());

        // 2) JSON + timestamp + konzole (hodí se pro audit nebo ingest do SIEM):
        ILogger log = new TimestampDecorator(
                          new JsonDecorator(
                              new ConsoleLogger(),
                              "encryptee"  // source
                          )
                      );

        // ----- Observer -----
        // Pozorovatel událostí používá výše definovaný logger (a jeho dekorátory).
        var observer = new ConsoleCryptoObserver(log);

        // Interaktivní UI v konzoli:
        Console.WriteLine("=== Encryptee ===");
        Console.WriteLine("Zvol mode: enc (encrypt) / dec (decrypt)");
        Console.Write("mode [enc/dec]: ");
        var mode = (Console.ReadLine() ?? "").Trim().ToLower();
        if (mode != "enc" && mode != "dec")
        {
            Console.WriteLine("Neplatný mode.");
            return;
        }

        Console.WriteLine("\nZvol algoritmus: 1=Caesar (didakticky), 2=XOR (didakticky), 3=AES (bezpečný)");
        Console.Write("algo [1/2/3]: ");
        var algoChoice = (Console.ReadLine() ?? "").Trim();

        // Vybereme konkrétní strategii podle volby uživatele (Strategy pattern v praxi).
        IEncryptStrategy strategy = algoChoice switch
        {
            "1" => SelectCaesar(),          // Caesar se ptá navíc na posun (viz metoda níže)
            "2" => new XorStrategy(),
            "3" => new AesPbkdf2Strategy(),
            _   => new AesPbkdf2Strategy(), // default: když někdo zadá něco jiného, použij AES
        };

        Console.WriteLine("\nZadej vstupní text:");
        var input = Console.ReadLine() ?? "";

        // Heslo/klíč:
        // - Caesar: ignoruje (má vlastní "shift")
        // - XOR/AES: vyžadují klíč/heslo (string)
        string keyOrPass;
        if (strategy is CaesarStrategy)
        {
            keyOrPass = ""; // pro Caesar není potřeba – posun jsme už zadali dříve
        }
        else
        {
            Console.Write("Zadej heslo/klíč: ");
            keyOrPass = Console.ReadLine() ?? "";
        }

        // Vytvoříme engine s vybranou strategií a observerem a spustíme operaci.
        var engine = new EncrypteeEngine(strategy, observer);
        engine.Run(mode, input, keyOrPass);

        Console.WriteLine("\nHotovo. Enter pro konec.");
        Console.ReadLine();
    }

    // Pomocná metoda pro dotaz na posun Caesaru a vytvoření CaesarStrategy.
    private static IEncryptStrategy SelectCaesar()
    {
        Console.Write("Caesar shift (např. 3): ");
        if (!int.TryParse(Console.ReadLine(), out var shift)) shift = 3; // fallback = 3
        return new CaesarStrategy(shift);
    }
}
#endregion
