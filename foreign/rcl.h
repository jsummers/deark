// See the file readme-rcl.txt for more information about this file.

// This is the original notice from the recoil.fu source file:
// ----------------------------------------
// Copyright (C) 2009-2026 Piotr Fusik
// SPDX-License-Identifier: MIT
// ----------------------------------------
// See LICENSE-rcl for the full license.

// Modifications for Deark are Copyright (C) 2026 Jason Summers, and have the
// same terms of use as the main part of Deark.
// Alternatively, at your option, the modifications for Deark may be treated
// as public domain.

#define RCLbool  unsigned char
#define RCLfalse 0
#define RCLtrue  1
struct RECOIL;
typedef struct RECOIL RECOIL;

typedef enum {
	RECOILResolution_AMIGA1X1,
	RECOILResolution_AMIGA2X1,
	RECOILResolution_AMIGA4X1,
	RECOILResolution_AMIGA8X1,
	RECOILResolution_AMIGA1X2,
	RECOILResolution_AMIGA1X4,
	RECOILResolution_AMIGA_DCTV1X1,
	RECOILResolution_AMIGA_DCTV1X2,
	RECOILResolution_ST1X2,
} RECOILResolution;

typedef struct {
	int (*readFile)(const RECOIL *self, const char *filename, u8 *content, int contentLength);
} RECOILVtbl;

struct RECOIL {
	const RECOILVtbl *vtbl;
	deark *de_c;
	de_bitmap *de_img;
	/**
	* Decoded image width.
	*/
	int width;
	/**
	* Decoded image height.
	*/
	int height;
	/**
	* Platform and pixel ratio.
	*/
	RECOILResolution resolution;
	/**
	* Number of frames (normally 1; 2 or 3 for flickering pictures).
	*/
	int frames;
	/**
	* RGB palette decoded from the image file.
	*/
	int contentPalette[256];
	int colors;
	int palette[256];
};

static int RECOIL_ReadFile(const RECOIL *self, const char *filename, u8 *content, int contentLength);

static void RECOIL_Construct(RECOIL *self, deark *de_c)
{
	static const RECOILVtbl vtbl = {
		RECOIL_ReadFile,
	};
	de_zeromem(self, sizeof(RECOIL));
	self->de_c = de_c;
	self->vtbl = &vtbl;
}

static void RECOIL_Destruct(RECOIL *self)
{
}

static RECOIL *RECOIL_New(deark *de_c)
{
	RECOIL *self = (RECOIL *) de_malloc(de_c, sizeof(RECOIL));
	if (self != NULL)
		RECOIL_Construct(self, de_c);
	return self;
}

static void RECOIL_Delete(RECOIL *self)
{
	if (self == NULL)
		return;
	RECOIL_Destruct(self);
	de_free(self->de_c, self);
}

static RCLbool RECOIL_SetSize(RECOIL *self, int width, int height, RECOILResolution resolution, int frames)
{
	if (width <= 0 || height <= 0 || height > 134217728 / width / frames)
		return RCLfalse;
	self->width = width;
	self->height = height;
	self->resolution = resolution;
	self->frames = frames;
	self->colors = -1;
	return RCLtrue;
}

static RCLbool RECOIL_SetScaledSize(RECOIL *self, int width, int height, RECOILResolution resolution)
{
	return RECOIL_SetSize(self, width, height, resolution, 1);
}

static void RECOIL_SetScaledPixel(RECOIL *self, int x, int y, int rgb)
{
	de_bitmap_setpixel_rgb(self->de_img, x, y, (de_color)rgb);
}

static int RECOIL_ReadFile(const RECOIL *self, const char *filename, u8 *content, int contentLength)
{
	return -1;
}

static int RECOIL_GetBitplanePixel(u8 const *content, int contentOffset, int x, int bitplanes, int bytesPerBitplane)
{
	int bit = ~x & 7;
	int c = 0;
	for (int bitplane = bitplanes; --bitplane >= 0;)
		c = c << 1 | (content[contentOffset + bitplane * bytesPerBitplane] >> bit & 1);
	return c;
}

static int RECOIL_GetBitplaneWordsPixel(u8 const *content, int contentOffset, int x, int bitplanes)
{
	return RECOIL_GetBitplanePixel(content, contentOffset + (x >> 3 & ~1) * bitplanes + (x >> 3 & 1), x, bitplanes, 2);
}

static RECOILResolution RECOIL_GetAmigaAspectRatio(int xRatio, int yRatio, RECOILResolution resolution)
{
	if (xRatio <= 0 || yRatio <= 0)
		return resolution;
	if (xRatio > yRatio * 6)
		return RECOILResolution_AMIGA8X1;
	if (xRatio > yRatio * 3)
		return RECOILResolution_AMIGA4X1;
	if (xRatio * 2 > yRatio * 3)
		return RECOILResolution_AMIGA2X1;
	if (yRatio > xRatio * 3)
		return RECOILResolution_AMIGA1X4;
	if (yRatio * 2 > xRatio * 3)
		return resolution == RECOILResolution_AMIGA1X1 ? RECOILResolution_AMIGA1X2 : RECOILResolution_ST1X2;
	return resolution;
}

static int RECOIL_GetDctvValue(const RECOIL *self, u8 const *content, int contentOffset, int x, int bitplanes)
{
	int c = RECOIL_GetBitplaneWordsPixel(content, contentOffset, x, bitplanes);
	int rgb = self->contentPalette[c];
	return (rgb << 2 & 64) | (rgb >> 19 & 16) | (rgb >> 5 & 4) | (rgb >> 15 & 1);
}

static RCLbool RECOIL_IsDctv(const RECOIL *self, u8 const *content, int contentOffset, int bitplanes)
{
	return RCLtrue;
}

static int RECOIL_ClampByte(int x)
{
	return x <= 0 ? 0 : x >= 255 ? 255 : x;
}

static RCLbool RECOIL_DecodeDctv(RECOIL *self, u8 const *content, int width, int height, RECOILResolution resolution, int bitplanes)
{
	if (!RECOIL_IsDctv(self, content, 0, bitplanes))
		return RCLfalse;
	int interlace;
	int bytesPerLine = ((width + 15) >> 4 << 1) * bitplanes;
	if (resolution == RECOILResolution_AMIGA1X2) {
		interlace = 0;
		height--;
		resolution = RECOILResolution_AMIGA_DCTV1X2;
	}
	else {
		if (!RECOIL_IsDctv(self, content, bytesPerLine, bitplanes))
			return RCLfalse;
		interlace = 1;
		height -= 2;
		resolution = RECOILResolution_AMIGA_DCTV1X1;
	}
	RECOIL_SetScaledSize(self, width, height, resolution);
	de_dbg(self->de_c, "DCTV interlace mode: %d", interlace);
	int contentOffset = bytesPerLine << interlace;
	int chroma[2048];
	for (int y = 0; y < height; y++) {
		int odd = y >> interlace & 1;
		int rgb = 0;
		int o = 0;
		int p = 0;
		for (int x = 0; x < width; x++) {
			if ((x & 1) == odd) {
				int n = x + 1 < width ? RECOIL_GetDctvValue(self, content, contentOffset, x, bitplanes) << 1 | RECOIL_GetDctvValue(self, content, contentOffset, x + 1, bitplanes) : 0;
				int i = (o + n) >> 1;
				i = i <= 64 ? 0 : i >= 224 ? 255 : (i - 64) * 8 / 5;
				int u = n + p - (o << 1);
				if (u < 0)
					u += 3;
				u >>= 2;
				if (((x + 1) & 2) == 0)
					u = -u;
				int chromaOffset = (x & ~1) | (y & interlace);
				int v = y > interlace ? chroma[chromaOffset] : 0;
				chroma[chromaOffset] = u;
				if (odd == 0) {
					u = v;
					v = chroma[chromaOffset];
				}
				p = o;
				o = n;
				int r = i + v * 4655 / 2560;
				int b = i + u * 8286 / 2560;
				int g = i - (v * 2372 + u * 1616) / 2560;
				rgb = RECOIL_ClampByte(r) << 16 | RECOIL_ClampByte(g) << 8 | RECOIL_ClampByte(b);
			}
			RECOIL_SetScaledPixel(self, x, y, rgb);
		}
		contentOffset += bytesPerLine;
	}
	return RCLtrue;
}
