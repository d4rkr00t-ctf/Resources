Image forensics as in you get a jpg or png as challenge? Usually you have to learn a bit about image formats.

If yes, here is my list of default things to do.

- First: Look at the image. Maybe it tells you something important.

- Use binwalk to check for other file type signatures in the image file.

- Use Exiftool to check for any interesting exif-metadata.

- Use stegsolve and switch through the layers and look for abnormalities.

Maybe the Flag is painted in the LSB image, or some QR-Code.

Maybe there are random pixels that look strange in a certain layer, that's a hint for Bit-Stego.

- Use zsteg to automatically test the most common bitstegos and sort by %ascii-in-results. (This one auto-solves about 50% of all image stego challenges)

- If the file is a png, you can check if the IDAT chunks are all correct and correctly ordered.

- Check with the strings tool for parts of the flag. If you found for example "CTF{W" in a chunk, check what is on that position in other IDAT chunks.

The harder ones can be a lot more tricky though.. JPG coefficiency manipulation, Frequency analysis, ...

But usually those are frowned upon, because they require a lot of guessing (if no hiding tool is provided)
