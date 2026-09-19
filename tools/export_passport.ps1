param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

Add-Type -AssemblyName System.Drawing

$targetPixels = 413
$targetPpi = 300
$jpegQuality = 92L

$outputDirectory = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

$source = [System.Drawing.Image]::FromFile($InputPath)
try {
    # Normalize common EXIF orientations before calculating the square crop.
    if ($source.PropertyIdList -contains 274) {
        $orientation = [BitConverter]::ToUInt16($source.GetPropertyItem(274).Value, 0)
        $rotation = switch ($orientation) {
            2 { [System.Drawing.RotateFlipType]::RotateNoneFlipX }
            3 { [System.Drawing.RotateFlipType]::Rotate180FlipNone }
            4 { [System.Drawing.RotateFlipType]::Rotate180FlipX }
            5 { [System.Drawing.RotateFlipType]::Rotate90FlipX }
            6 { [System.Drawing.RotateFlipType]::Rotate90FlipNone }
            7 { [System.Drawing.RotateFlipType]::Rotate270FlipX }
            8 { [System.Drawing.RotateFlipType]::Rotate270FlipNone }
            default { [System.Drawing.RotateFlipType]::RotateNoneFlipNone }
        }
        $source.RotateFlip($rotation)
    }

    # Use a centered square crop. A slight upward bias keeps the full hair and
    # upper shoulders in the standard passport-photo composition.
    $cropSize = [math]::Min($source.Width, $source.Height)
    $cropX = [math]::Floor(($source.Width - $cropSize) / 2)
    $cropY = [math]::Max(0, [math]::Floor(($source.Height - $cropSize) / 2) - 168)
    if (($cropY + $cropSize) -gt $source.Height) {
        $cropY = $source.Height - $cropSize
    }

    $bitmap = New-Object System.Drawing.Bitmap($targetPixels, $targetPixels, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
    try {
        $bitmap.SetResolution($targetPpi, $targetPpi)
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        try {
            $graphics.Clear([System.Drawing.Color]::White)
            $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
            $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
            $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
            $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $destination = New-Object System.Drawing.Rectangle(0, 0, $targetPixels, $targetPixels)
            $sourceCrop = New-Object System.Drawing.Rectangle($cropX, $cropY, $cropSize, $cropSize)
            $graphics.DrawImage($source, $destination, $sourceCrop, [System.Drawing.GraphicsUnit]::Pixel)
        }
        finally {
            $graphics.Dispose()
        }

        $jpegCodec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() |
            Where-Object { $_.MimeType -eq 'image/jpeg' }
        $encoderParameters = New-Object System.Drawing.Imaging.EncoderParameters(1)
        $encoderParameters.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter(
            [System.Drawing.Imaging.Encoder]::Quality,
            $jpegQuality
        )
        try {
            $bitmap.Save($OutputPath, $jpegCodec, $encoderParameters)
        }
        finally {
            $encoderParameters.Dispose()
        }
    }
    finally {
        $bitmap.Dispose()
    }
}
finally {
    $source.Dispose()
}

$check = [System.Drawing.Image]::FromFile($OutputPath)
try {
    $file = Get-Item -LiteralPath $OutputPath
    [pscustomobject]@{
        Path = $file.FullName
        Format = $check.RawFormat.Guid
        WidthPixels = $check.Width
        HeightPixels = $check.Height
        HorizontalPpi = [math]::Round($check.HorizontalResolution, 2)
        VerticalPpi = [math]::Round($check.VerticalResolution, 2)
        WidthMm = [math]::Round(($check.Width / $check.HorizontalResolution) * 25.4, 3)
        HeightMm = [math]::Round(($check.Height / $check.VerticalResolution) * 25.4, 3)
        Bytes = $file.Length
        Kilobytes = [math]::Round($file.Length / 1KB, 2)
    }
}
finally {
    $check.Dispose()
}
