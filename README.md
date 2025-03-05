# steganography
Yo, this is your go-to Python app if you wanna stash secret stuff inside images like a pro. We’re talking full-on AES-256 encryption wrapped in some clean stego magic, all with a chill Tkinter GUI that even your grandma could use. Hide your texts, files, whatever — no one’s gonna suspect a thing. Lock it up, keep it tight, stay sneaky.

This software is basically a stealthy combo of image manipulation, encryption, and a simple GUI to tie it all together. Up front, it’s rocking Tkinter for the interface, so you’ve got buttons and text fields to do all your dirty work without touching the terminal. Super user-friendly, even if you don’t know jack about coding.

Behind the scenes, we’re using Pillow (PIL) to handle the images. This is what lets us open up any standard pic — like PNGs or BMPs — and tweak the pixels without messing up the whole vibe of the photo. The trick is hiding your encrypted data inside the Least Significant Bits (LSB) of each pixel. It's lowkey genius because your eye can't even tell the difference.

Then we’ve got PyCryptodome, which is doing the heavy lifting on the encryption side. We're rolling with AES-256-CBC, which is military-grade stuff. So first, your secret text or file gets locked up with your password, and only then does it get buried in the image. No password, no party.

Here’s the flow: you pick an image, type your password, and decide if you wanna hide a simple text message or an actual file. The app encrypts the payload, slaps a little header on it to keep track of what’s inside, and spreads the encrypted bits across the image pixels. You save the new "secret" image, and boom, you’re good.

When it’s time to pull your data back out, you load up the image, punch in the password, and the app digs through the pixels to pull out the hidden bits, decrypts them, and gives you your goodies back. If the password’s wrong or someone messes with the image? Forget it. It just won’t work.

Basically, it’s like turning any ordinary image into a locked vault. But instead of looking like a vault, it still looks like your average cat photo. Nobody’s ever gonna know unless you tell ‘em.
