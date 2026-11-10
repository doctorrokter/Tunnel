/*
 * bb-shared / ui / BbSharedDimens.hpp - puts the shared Dimens into a QML context as `dimens`.
 *
 * Opt-in with CONFIG += bb_shared_dimens. Then, for every QML document that lays out with `dimens` -
 * the scene AND an Active Frame cover alike:
 *
 *     #include "BbSharedDimens.hpp"
 *     bbshared::installDimensContext(qml->documentContext()->engine()->rootContext());
 *
 * One instance per process, created on first use and parented to the application (a local static in
 * an inline function is one instance across translation units, as in L10n and BbSharedImages).
 */
#ifndef BBSHARED_BBSHAREDDIMENS_HPP
#define BBSHARED_BBSHAREDDIMENS_HPP

#include "Dimens.hpp"

#include <QCoreApplication>
#include <QDeclarativeContext>

namespace bbshared {

inline Dimens* sharedDimens()
{
    static Dimens* dimens = 0;
    if (!dimens) {
        dimens = new Dimens(QCoreApplication::instance());
    }
    return dimens;
}

inline void installDimensContext(QDeclarativeContext* ctx)
{
    if (!ctx) {
        return;
    }
    ctx->setContextProperty(QLatin1String("dimens"), sharedDimens());
}

} // namespace bbshared

#endif // BBSHARED_BBSHAREDDIMENS_HPP
