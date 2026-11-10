import bb.cascades 1.4
import bb.cascades.multimedia 1.0

/*
 * QrScanPage - a profile from a QR code (docs/APP.md, section 5): the rear camera with Cascades'
 * BarcodeDetector (QR codes by default). A WireGuard or AmneziaWG QR code holds the .conf text; the
 * first code read goes to main.qml (found), which pops the page and opens the import sheet - the
 * daemon checks the text there. AmneziaVPN shows a key as a series of codes that it changes by
 * itself: the page keeps reading until it has every part (importer.qrFeed) and says how far it got.
 * The camera is let go in cleanup() (main.qml, when the page goes).
 */
Page {
    id: page

    // The first code read: once.
    property bool done: false
    property bool failed: false
    // AmneziaVPN's series: the parts read so far and how many there are (0 - no series).
    property int partsRead: 0
    property int partsTotal: 0

    signal found(string text)

    function cleanup() {
        camera.close();
    }

    titleBar: TitleBar {
        title: qsTr("Scan a QR code") + Retranslate.onLocaleOrLanguageChanged
    }

    Container {
        layout: DockLayout {
        }

        Camera {
            id: camera
            horizontalAlignment: HorizontalAlignment.Fill
            verticalAlignment: VerticalAlignment.Fill

            onCameraOpened: {
                camera.startViewfinder();
            }

            onCameraOpenFailed: {
                page.failed = true;
            }

            attachedObjects: [
                BarcodeDetector {
                    id: detector
                    camera: camera
                    formats: BarcodeFormat.QrCode
                    onDetected: {
                        if (page.done) {
                            return;
                        }
                        var r = importer.qrFeed(data);
                        if (r.state === "part") {
                            page.partsRead = r.received;
                            page.partsTotal = r.total;
                            return;
                        }
                        page.done = true;
                        camera.stopViewfinder();
                        page.found(r.text);
                    }
                }
            ]
        }

        Container {
            horizontalAlignment: HorizontalAlignment.Fill
            verticalAlignment: VerticalAlignment.Bottom
            topPadding: ui.du(dimens.pad)
            leftPadding: ui.du(dimens.pad)
            rightPadding: ui.du(dimens.pad)
            bottomPadding: ui.du(dimens.pad)
            background: Color.create("#99000000")

            Label {
                horizontalAlignment: HorizontalAlignment.Center
                text: (page.failed
                        ? qsTr("The camera cannot be opened.")
                        : (page.partsTotal > 0
                                ? qsTr("An AmneziaVPN key: part %1 of %2. Keep the camera on its codes - they change by themselves.").arg(page.partsRead).arg(page.partsTotal)
                                : qsTr("Point the camera at the profile's QR code."))) + Retranslate.onLocaleOrLanguageChanged
                textStyle.color: Color.White
                textStyle.textAlign: TextAlign.Center
                multiline: true
            }
        }
    }

    onCreationCompleted: {
        importer.qrReset();
        camera.open(CameraUnit.Rear);
    }
}
