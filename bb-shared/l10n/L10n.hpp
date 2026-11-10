/*
 * bb-shared / l10n / L10n.hpp — language resolution, QLocale, the settings-picker model and
 * translator loading. This module is the ONE place the rest of the code talks to for anything
 * language-related: no `== "ru"`, no `QLocale(... ? Russian : English)`, no per-language `if`.
 *
 * The module is language-AGNOSTIC and self-configuring. An app calls init("<Prefix>") ONCE at
 * startup; the module then SCANS the shipped <Prefix>_<code>.qm catalogs itself and builds the
 * language map — so no app ever re-implements the parsing (no copy-paste), yet the app stays the
 * source of truth: the truth is simply which catalogs it ships. By our convention the default /
 * base language is ALWAYS English (the tr() source); the map holds only the OTHERS. "Ship a
 * translation = support the language" — the GUI and the headless service each init() with their own
 * prefix and derive their own set independently, sharing no data.
 *
 * English has a catalog too, the BASE one (<Prefix>.qm, no code), and it is loaded for English -
 * for its PLURALS. A source literal cannot say "1 member" and "5 members" at once, so a
 * tr("%n member(s)", "", n) printed "5 member(s)" in an English UI until the base catalog carried
 * the two forms (lrelease needs `language="en"` on the base .ts for English plural rules). Every other
 * base entry is empty or equal to its source, so loading it changes nothing else.
 *
 * "SYSTEM" MEANS THE DEVICE'S UI DISPLAY LANGUAGE (Settings > Language and Input > Language),
 * never the region: a Russian phone set to a Canadian region is still Russian. It is asked of
 * bb::system::LocaleHandler(LocaleType::Messages) - the platform's own answer "for string
 * localization", the same in a GUI app and a headless service. NOT QLocale::system(): on BB10
 * that is neither the language nor the region - a Passport with Language AND Region Russian
 * reported en_US there, and every "system" setting came up English on it while an identically
 * configured Passport was fine (2026-09-11, BBMigrator's diagnostics).
 *
 * Header-only (inline) so it drops into any BB10 project — GUI or headless service — via a single
 * INCLUDEPATH (bb-shared.pri). The state is a function-local static in an inline function, so
 * there is exactly ONE instance per process even across translation units. Depends on QtCore and
 * bbsystem (LocaleHandler); bb-shared.pri links -lbbsystem.
 *
 * Formatting policy is OPTION B: the app's CHOSEN language drives QLocale (dates & numbers), not
 * just the translated strings (see locale()). Fallbacks at every layer (resolve -> default, tr()
 * -> source, QLocale -> default) mean a half-added / half-translated language degrades, never breaks.
 */
#ifndef BBSHARED_L10N_HPP
#define BBSHARED_L10N_HPP

#include <QString>      // also brings QLatin1String / QLatin1Char
#include <QChar>
#include <QLocale>
#include <QList>
#include <QStringList>
#include <QDir>
#include <QVariant>     // also brings the QVariantList / QVariantMap typedefs
#include <QTranslator>
#include <QCoreApplication>

#include <bb/system/LocaleHandler>
#include <bb/system/LocaleType>

namespace bbshared {

// One supported language: its QLocale/BCP-47 code ("ru", "pl") and the label shown in the picker
// (always in its own language, never translated).
struct Lang {
    QString code;
    QString nativeName;
};

namespace L10n {

// The base / default language — the tr() source language and the fallback. Our convention: always
// English. This is the only language fact the module itself holds; the rest it derives from init().
inline QString defaultCode()
{
    return QString::fromLatin1("en");
}

// Process-wide state, filled by init(). A local static in an inline function = exactly one
// instance per process, shared across all translation units.
struct State {
    QList<Lang> langs;  // the OTHER (non-default) languages, discovered from the shipped catalogs
    QString prefix;     // catalog prefix, e.g. "BBHealth" / "BBHealthService"
    QString dir;        // where the .qm live, e.g. "app/native/qm"
    QString systemLang; // the device's UI display language ("ru"), cached; "" = not asked yet
};

inline State& state()
{
    static State s;
    return s;
}

// Asks the platform for the device's UI display language, as a bare code ("ru"). The region
// plays no part. Falls back to QLocale() - which Cascades sets from the UI language in a GUI
// app - only if the platform gives no usable answer.
inline QString queryUiLanguage()
{
    QString code;
    if (QCoreApplication::instance()) {
        bb::system::LocaleHandler messages(bb::system::LocaleType::Messages);
        code = messages.locale().name().section(QLatin1Char('_'), 0, 0);
    }
    if (code.isEmpty() || code == QLatin1String("C")) {
        code = QLocale().name().section(QLatin1Char('_'), 0, 0);
    }
    return code;
}

// The device's UI display language ("ru"), cached. init() and installTranslator() refresh it on
// the main thread, so readers on other threads only ever read.
inline QString systemLanguage()
{
    State& s = state();
    if (s.systemLang.isEmpty()) {
        s.systemLang = queryUiLanguage();
    }
    return s.systemLang;
}

// Re-reads the device language - after the user changed it in Settings. installTranslator()
// does this on every call, and apps call it on LocaleHandler's systemLanguageChanged anyway.
inline void refreshSystemLanguage()
{
    state().systemLang = queryUiLanguage();
}

// The display name for a language code, first letter capitalised (Qt gives lower-case endonyms
// for many languages). Other languages use their native endonym ("pl" -> "Polski", "ru" ->
// "Русский"); the BASE language uses its plain language name, because Qt's endonym for it is
// country-qualified (en -> en_US -> "American English" / "U.S. English") and we just want "English".
inline QString nativeNameFor(const QString& code)
{
    QString n = (code == defaultCode())
        ? QLocale::languageToString(QLocale(code).language()) // base: "English", not "U.S. English"
        : QLocale(code).nativeLanguageName();                 // others: the native endonym
    if (n.isEmpty()) {
        n = code;
    } else {
        n[0] = n[0].toUpper();
    }
    return n;
}

// Point the module at an app's catalogs and let it build the language map ITSELF: every
// <prefix>_<code>.qm in `dir` (skipping the base <prefix>.qm, which is English) becomes a
// supported language, its label taken from Qt. Call once at startup, on the main thread and after
// the application object exists, before anything resolves a language. The app supplies only its
// prefix — the parsing lives here, shared by every project.
inline void init(const QString& prefix, const QString& dir = QString::fromLatin1("app/native/qm"))
{
    State& s = state();
    s.prefix = prefix;
    s.dir = dir;
    s.langs.clear();

    QDir d(dir);
    QStringList filters;
    filters << (prefix + QString::fromLatin1("_*.qm")); // "BBHealth_*.qm" (not the base "BBHealth.qm")
    const QStringList files = d.entryList(filters, QDir::Files, QDir::Name);
    for (int i = 0; i < files.size(); ++i) {
        QString code = files.at(i);
        code = code.mid(prefix.length() + 1); // drop "<prefix>_"
        code.chop(3);                          // drop ".qm"
        if (code.isEmpty() || code == defaultCode()) {
            continue;
        }
        Lang l;
        l.code = code;
        l.nativeName = nativeNameFor(code);
        s.langs << l;
    }
    refreshSystemLanguage();
}

inline bool isSupported(const QString& code)
{
    if (code == defaultCode()) {
        return true; // the base language is always supported
    }
    const QList<Lang>& langs = state().langs;
    for (int i = 0; i < langs.size(); ++i) {
        if (langs.at(i).code == code) {
            return true;
        }
    }
    return false;
}

// The label for a code ("Polski"), in its own language; "" if unknown.
inline QString nativeName(const QString& code)
{
    const QList<Lang>& langs = state().langs;
    for (int i = 0; i < langs.size(); ++i) {
        if (langs.at(i).code == code) {
            return langs.at(i).nativeName;
        }
    }
    return QString();
}

// Resolve a stored setting to a concrete SUPPORTED code:
//   supported explicit code -> itself; "system"/"" -> the device's UI display language if we
//   support it; anything else -> the default.
inline QString resolve(const QString& setting)
{
    if (isSupported(setting)) {
        return setting;
    }
    if (setting.isEmpty() || setting == QLatin1String("system")) {
        const QString lang = systemLanguage();
        if (isSupported(lang)) {
            return lang;
        }
    }
    return defaultCode();
}

// QLocale for the resolved language (option B: the chosen language drives dates & numbers).
inline QLocale locale(const QString& setting)
{
    return QLocale(resolve(setting));
}

// The OTHER (non-default) languages as [{ "code", "name" }], for a data-driven picker. The picker
// adds "System" and the explicit default (English) itself — they are not in this list.
inline QVariantList languages()
{
    QVariantList out;
    const QList<Lang>& langs = state().langs;
    for (int i = 0; i < langs.size(); ++i) {
        QVariantMap m;
        m.insert(QLatin1String("code"), langs.at(i).code);
        m.insert(QLatin1String("name"), langs.at(i).nativeName);
        out << m;
    }
    return out;
}

// ALL concrete languages as [{ "code", "name" }]: the default (English) first, then the others
// from the registry. For pickers that list every language explicitly (onboarding), as opposed to
// languages() (others only) used where the picker adds System + English itself.
inline QVariantList allLanguages()
{
    QVariantList out;
    QVariantMap def;
    def.insert(QLatin1String("code"), defaultCode());
    def.insert(QLatin1String("name"), nativeNameFor(defaultCode()));
    out << def;
    out += languages();
    return out;
}

// Load <prefix>_<resolved>.qm (prefix/dir from init()) into `tr` and install it, removing any
// prior install of the SAME translator first so a live language switch replaces cleanly. The base
// language loads the base catalog, <prefix>.qm - its strings are the source literals, but its
// PLURAL forms are not (see the note at the top); an app that ships no base catalog simply gets
// none installed, as before. Re-reads the device language first, so "system" follows a change made
// in Settings. Returns the applied code.
inline QString installTranslator(QTranslator* tr, const QString& setting)
{
    refreshSystemLanguage();
    const QString lang = resolve(setting);
    const State& s = state();
    QCoreApplication* app = QCoreApplication::instance();
    if (tr && app) {
        app->removeTranslator(tr);
        const QString catalog = (lang == defaultCode())
            ? s.prefix                                  // "BBTelega"    -> BBTelega.qm
            : (s.prefix + QLatin1Char('_') + lang);     // "BBTelega_ru" -> BBTelega_ru.qm
        if (tr->load(catalog, s.dir)) {
            app->installTranslator(tr);
        }
    }
    return lang;
}

} // namespace L10n
} // namespace bbshared

#endif // BBSHARED_L10N_HPP
