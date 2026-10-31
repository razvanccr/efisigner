import AppKit

// Draws a shield with a key and writes an .icns via iconutil.
func render(_ size: CGFloat) -> NSImage {
    let img = NSImage(size: NSSize(width: size, height: size))
    img.lockFocus()
    let s = size
    // dark glass squircle background
    let bgRect = NSRect(x: s*0.05, y: s*0.05, width: s*0.9, height: s*0.9)
    let bg = NSBezierPath(roundedRect: bgRect, xRadius: s*0.21, yRadius: s*0.21)
    NSGradient(starting: NSColor(white: 0.21, alpha: 1), ending: NSColor(white: 0.08, alpha: 1))!.draw(in: bg, angle: -90)
    // soft top highlight
    NSGraphicsContext.saveGraphicsState()
    bg.addClip()
    let hl = NSGradient(colorsAndLocations: (NSColor(white: 1, alpha: 0.16), 0.0), (NSColor(white: 1, alpha: 0.0), 1.0))!
    hl.draw(in: NSRect(x: s*0.05, y: s*0.55, width: s*0.9, height: s*0.4), angle: -90)
    NSGraphicsContext.restoreGraphicsState()
    // thin inner rim
    let rim = NSBezierPath(roundedRect: bgRect.insetBy(dx: s*0.008, dy: s*0.008), xRadius: s*0.2, yRadius: s*0.2)
    NSColor(white: 1, alpha: 0.10).setStroke(); rim.lineWidth = s*0.012; rim.stroke()
    // shield: muted slate with a subtle vertical gradient and a soft light outline
    let shield = NSBezierPath()
    shield.move(to: NSPoint(x: s*0.5, y: s*0.84))
    shield.line(to: NSPoint(x: s*0.77, y: s*0.73))
    shield.curve(to: NSPoint(x: s*0.5, y: s*0.16), controlPoint1: NSPoint(x: s*0.77, y: s*0.43), controlPoint2: NSPoint(x: s*0.67, y: s*0.26))
    shield.curve(to: NSPoint(x: s*0.23, y: s*0.73), controlPoint1: NSPoint(x: s*0.33, y: s*0.26), controlPoint2: NSPoint(x: s*0.23, y: s*0.43))
    shield.close()
    NSGradient(starting: NSColor(calibratedRed: 0.36, green: 0.40, blue: 0.47, alpha: 1), ending: NSColor(calibratedRed: 0.20, green: 0.23, blue: 0.29, alpha: 1))!.draw(in: shield, angle: -90)
    NSColor(white: 1, alpha: 0.55).setStroke(); shield.lineWidth = s*0.022; shield.stroke()
    // key: ring + shaft + teeth, white with a faint shadow
    let shadow = NSShadow(); shadow.shadowColor = NSColor(white: 0, alpha: 0.45); shadow.shadowBlurRadius = s*0.02; shadow.shadowOffset = NSSize(width: 0, height: -s*0.01)
    NSGraphicsContext.saveGraphicsState(); shadow.set()
    NSColor(white: 0.97, alpha: 1).setStroke()
    let ring = NSBezierPath(ovalIn: NSRect(x: s*0.35, y: s*0.50, width: s*0.2, height: s*0.2)); ring.lineWidth = s*0.055; ring.stroke()
    let shaft = NSBezierPath(); shaft.lineWidth = s*0.055; shaft.lineCapStyle = .round
    shaft.move(to: NSPoint(x: s*0.52, y: s*0.54)); shaft.line(to: NSPoint(x: s*0.67, y: s*0.30)); shaft.stroke()
    for (dx, dy) in [(0.63, 0.365), (0.585, 0.435)] {
        let t = NSBezierPath(); t.lineWidth = s*0.05; t.lineCapStyle = .round
        t.move(to: NSPoint(x: s*dx, y: s*dy)); t.line(to: NSPoint(x: s*(dx+0.075), y: s*(dy+0.048))); t.stroke()
    }
    NSGraphicsContext.restoreGraphicsState()
    img.unlockFocus()
    return img
}

let tmp = URL(fileURLWithPath: CommandLine.arguments[1])
let iconset = tmp.appendingPathComponent("AppIcon.iconset")
try? FileManager.default.removeItem(at: iconset)
try! FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
for (name, px) in [("16x16",16),("16x16@2x",32),("32x32",32),("32x32@2x",64),("128x128",128),("128x128@2x",256),("256x256",256),("256x256@2x",512),("512x512",512),("512x512@2x",1024)] {
    let img = render(CGFloat(px))
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    img.draw(in: NSRect(x: 0, y: 0, width: px, height: px))
    NSGraphicsContext.restoreGraphicsState()
    try! rep.representation(using: .png, properties: [:])!.write(to: iconset.appendingPathComponent("icon_\(name).png"))
}
print("iconset at \(iconset.path)")
