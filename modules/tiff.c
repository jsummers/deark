// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Extract various things from TIFF (and similar) image files

#include <deark-config.h>
#include <deark-private.h>
#include "fmtutil.h"
DE_DECLARE_MODULE(de_module_tiff);

#define ITEMS_IN_ARRAY(x) (sizeof(x)/sizeof(x[0]))
#define MAX_IFDS 1000

#define DATATYPE_BYTE      1
#define DATATYPE_ASCII     2
#define DATATYPE_UINT16    3
#define DATATYPE_UINT32    4
#define DATATYPE_RATIONAL  5
#define DATATYPE_SBYTE     6
#define DATATYPE_UNDEF     7
#define DATATYPE_SINT16    8
#define DATATYPE_SINT32    9
#define DATATYPE_SRATIONAL 10
#define DATATYPE_FLOAT32   11
#define DATATYPE_FLOAT64   12
#define DATATYPE_IFD32     13
#define DATATYPE_UINT64    16
#define DATATYPE_SINT64    17
#define DATATYPE_IFD64     18

#define DE_TIFFFMT_TIFF       1
#define DE_TIFFFMT_BIGTIFF    2
#define DE_TIFFFMT_PANASONIC  3 // Panasonic RAW / RW2
#define DE_TIFFFMT_ORF        4 // Olympus RAW
#define DE_TIFFFMT_DCP        5 // DNG Camera Profile (DCP)
#define DE_TIFFFMT_MDI        6 // Microsoft Office Document Imaging

#define IFDTYPE_NORMAL       0
#define IFDTYPE_SUBIFD       1
#define IFDTYPE_EXIF         2
#define IFDTYPE_EXIFINTEROP  3
#define IFDTYPE_GPS          4

struct localctx_struct;
typedef struct localctx_struct lctx;
struct taginfo;
struct tagnuminfo;

struct ifdstack_item {
	de_int64 offset;
	int ifdtype;
};

typedef void (*handler_fn_type)(deark *c, lctx *d, const struct taginfo *tg,
	const struct tagnuminfo *tni);

static void handler_colormap(deark *c, lctx *d, const struct taginfo *tg, const struct tagnuminfo *tni);
static void handler_subifd(deark *c, lctx *d, const struct taginfo *tg, const struct tagnuminfo *tni);
static void handler_xmp(deark *c, lctx *d, const struct taginfo *tg, const struct tagnuminfo *tni);
static void handler_iptc(deark *c, lctx *d, const struct taginfo *tg, const struct tagnuminfo *tni);
static void handler_photoshoprsrc(deark *c, lctx *d, const struct taginfo *tg, const struct tagnuminfo *tni);
static void handler_iccprofile(deark *c, lctx *d, const struct taginfo *tg, const struct tagnuminfo *tni);

struct valdec_params {
	lctx *d;
	const struct taginfo *tg;
	de_int64 idx;
	de_int64 n;
};
struct valdec_result {
	size_t buf_len;
	char buf[200];
};

typedef int (*val_decoder_fn_type)(deark *c, const struct valdec_params *vp, struct valdec_result *vr);

// Forward declaration of value decoder functions
#define DECLARE_VALDEC(x) static int x(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
DECLARE_VALDEC(valdec_newsubfiletype);
DECLARE_VALDEC(valdec_oldsubfiletype);
DECLARE_VALDEC(valdec_compression);
DECLARE_VALDEC(valdec_photometric);
DECLARE_VALDEC(valdec_threshholding);
DECLARE_VALDEC(valdec_fillorder);
DECLARE_VALDEC(valdec_orientation);
DECLARE_VALDEC(valdec_planarconfiguration);
DECLARE_VALDEC(valdec_t4options);
DECLARE_VALDEC(valdec_t6options);
DECLARE_VALDEC(valdec_resolutionunit);
DECLARE_VALDEC(valdec_pagenumber);
DECLARE_VALDEC(valdec_predictor);
DECLARE_VALDEC(valdec_extrasamples);
DECLARE_VALDEC(valdec_sampleformat);
DECLARE_VALDEC(valdec_jpegproc);
DECLARE_VALDEC(valdec_ycbcrpositioning);
DECLARE_VALDEC(valdec_exposureprogram);
DECLARE_VALDEC(valdec_componentsconfiguration);
DECLARE_VALDEC(valdec_meteringmode);
DECLARE_VALDEC(valdec_lightsource);
DECLARE_VALDEC(valdec_flash);
DECLARE_VALDEC(valdec_exifcolorspace);
DECLARE_VALDEC(valdec_filesource);
DECLARE_VALDEC(valdec_scenetype);
DECLARE_VALDEC(valdec_sensingmethod);
DECLARE_VALDEC(valdec_customrendered);
DECLARE_VALDEC(valdec_exposuremode);
DECLARE_VALDEC(valdec_whitebalance);
DECLARE_VALDEC(valdec_scenecapturetype);
DECLARE_VALDEC(valdec_gaincontrol);
DECLARE_VALDEC(valdec_contrast);
DECLARE_VALDEC(valdec_saturation);
DECLARE_VALDEC(valdec_sharpness);
DECLARE_VALDEC(valdec_subjectdistancerange);
DECLARE_VALDEC(valdec_profileembedpolicy);
DECLARE_VALDEC(valdec_dngcolorspace);

struct tagnuminfo {
	int tagnum;

	// 0x08=suppress auto display of values
	// 0x10=this is an Exif tag
	// 0x20=an Exif Interoperability-IFD tag
	// 0x40=a GPS attribute tag
	// 0x80=a DNG tag
	// 0x0100=TIFF/EP
	unsigned int flags;

	const char *tagname;
	handler_fn_type hfn;
	val_decoder_fn_type vdfn;
};
static const struct tagnuminfo tagnuminfo_arr[] = {
	{ 254, 0x00, "NewSubfileType", NULL, valdec_newsubfiletype },
	{ 255, 0x00, "OldSubfileType", NULL, valdec_oldsubfiletype },
	{ 256, 0x00, "ImageWidth", NULL, NULL },
	{ 257, 0x00, "ImageLength", NULL, NULL },
	{ 258, 0x00, "BitsPerSample", NULL, NULL },
	{ 259, 0x00, "Compression", NULL, valdec_compression },
	{ 262, 0x00, "PhotometricInterpretation", NULL, valdec_photometric },
	{ 263, 0x00, "Threshholding", NULL, valdec_threshholding },
	{ 264, 0x00, "CellWidth", NULL, NULL },
	{ 265, 0x00, "CellLength", NULL, NULL },
	{ 266, 0x00, "FillOrder", NULL, valdec_fillorder },
	{ 269, 0x00, "DocumentName", NULL, NULL },
	{ 270, 0x00, "ImageDescription", NULL, NULL },
	{ 271, 0x00, "Make", NULL, NULL },
	{ 272, 0x00, "Model", NULL, NULL },
	{ 273, 0x00, "StripOffsets", NULL, NULL },
	{ 274, 0x00, "Orientation", NULL, valdec_orientation },
	{ 277, 0x00, "SamplesPerPixel", NULL, NULL },
	{ 278, 0x00, "RowsPerStrip", NULL, NULL },
	{ 279, 0x00, "StripByteCounts", NULL, NULL },
	{ 280, 0x00, "MinSampleValue", NULL, NULL },
	{ 281, 0x00, "MaxSampleValue", NULL, NULL },
	{ 282, 0x00, "XResolution", NULL, NULL },
	{ 283, 0x00, "YResolution", NULL, NULL },
	{ 284, 0x00, "PlanarConfiguration", NULL, valdec_planarconfiguration },
	{ 285, 0x00, "PageName", NULL, NULL },
	{ 286, 0x00, "XPosition", NULL, NULL },
	{ 287, 0x00, "YPosition", NULL, NULL },
	{ 288, 0x00, "FreeOffsets", NULL, NULL },
	{ 289, 0x00, "FreeByteCounts", NULL, NULL },
	{ 290, 0x00, "GrayResponseUnit", NULL, NULL },
	{ 291, 0x00, "GrayResponseCurve", NULL, NULL },
	{ 292, 0x00, "T4Options", NULL, valdec_t4options },
	{ 293, 0x00, "T6Options", NULL, valdec_t6options },
	{ 296, 0x00, "ResolutionUnit", NULL, valdec_resolutionunit },
	{ 297, 0x00, "PageNumber", NULL, valdec_pagenumber },
	{ 301, 0x00, "TransferFunction", NULL, NULL },
	{ 305, 0x00, "Software", NULL, NULL },
	{ 306, 0x00, "DateTime", NULL, NULL },
	{ 315, 0x00, "Artist", NULL, NULL },
	{ 316, 0x00, "HostComputer", NULL, NULL },
	{ 317, 0x00, "Predictor", NULL, valdec_predictor },
	{ 318, 0x00, "WhitePoint", NULL, NULL },
	{ 319, 0x00, "PrimaryChromaticities", NULL, NULL },
	{ 320, 0x08, "ColorMap", handler_colormap, NULL },
	{ 321, 0x00, "HalftoneHints", NULL, NULL },
	{ 322, 0x00, "TileWidth", NULL, NULL },
	{ 323, 0x00, "TileLength", NULL, NULL },
	{ 324, 0x00, "TileOffsets", NULL, NULL },
	{ 325, 0x00, "TileByteCounts", NULL, NULL },
	{ 326, 0x00, "BadFaxLines", NULL, NULL },
	{ 327, 0x00, "CleanFaxData", NULL, NULL },
	{ 328, 0x00, "ConsecutiveBadFaxLines", NULL, NULL },
	{ 330, 0x08, "SubIFD", handler_subifd, NULL },
	{ 332, 0x00, "InkSet", NULL, NULL },
	{ 333, 0x00, "InkNames", NULL, NULL },
	{ 334, 0x00, "NumberOfInks", NULL, NULL },
	{ 336, 0x00, "DotRange", NULL, NULL },
	{ 337, 0x00, "TargetPrinter", NULL, NULL },
	{ 338, 0x00, "ExtraSamples", NULL, valdec_extrasamples },
	{ 339, 0x00, "SampleFormat", NULL, valdec_sampleformat },
	{ 340, 0x00, "SMinSampleValue", NULL, NULL },
	{ 341, 0x00, "SMaxSampleValue", NULL, NULL },
	{ 342, 0x00, "TransferRange", NULL, NULL },
	{ 347, 0x00, "JPEGTables", NULL, NULL },
	{ 512, 0x00, "JPEGProc", NULL, valdec_jpegproc },
#define TAG_JPEGINTERCHANGEFORMAT 513
	{ TAG_JPEGINTERCHANGEFORMAT, 0x00, "JPEGInterchangeFormat", NULL, NULL },
#define TAG_JPEGINTERCHANGEFORMATLENGTH 514
	{ TAG_JPEGINTERCHANGEFORMATLENGTH, 0x00, "JPEGInterchangeFormatLength", NULL, NULL },
	{ 515, 0x00, "JPEGRestartInterval", NULL, NULL },
	{ 517, 0x00, "JPEGLosslessPredictors", NULL, NULL },
	{ 518, 0x00, "JPEGPointTransforms", NULL, NULL },
	{ 519, 0x00, "JPEGQTables", NULL, NULL },
	{ 520, 0x00, "JPEGDCTables", NULL, NULL },
	{ 521, 0x00, "JPEGACTables", NULL, NULL },
	{ 529, 0x00, "YCbCrCoefficients", NULL, NULL },
	{ 530, 0x00, "YCbCrSubSampling", NULL, NULL },
	{ 531, 0x00, "YCbCrPositioning", NULL, valdec_ycbcrpositioning },
	{ 532, 0x00, "ReferenceBlackWhite", NULL, NULL },
	{ 700, 0x08, "XMP", handler_xmp, NULL },
	{ 32932, 0x00, "Annotation Data", NULL, NULL },
	{ 32995, 0x00, "Matteing(SGI)", NULL, NULL },
	{ 32996, 0x00, "DataType(SGI)", NULL, NULL },
	{ 32997, 0x00, "ImageDepth(SGI)", NULL, NULL },
	{ 32998, 0x00, "TileDepth(SGI)", NULL, NULL },
	{ 33421, 0x0100, "CFARepeatPatternDim", NULL, NULL },
	{ 33422, 0x0100, "CFAPattern", NULL, NULL },
	{ 33423, 0x0100, "BatteryLevel", NULL, NULL },
	{ 33432, 0x00, "Copyright", NULL, NULL },
	{ 33434, 0x10, "ExposureTime", NULL, NULL },
	{ 33437, 0x10, "FNumber", NULL, NULL },
	{ 33723, 0x08, "IPTC", handler_iptc, NULL },
	{ 34377, 0x08, "PhotoshopImageResources", handler_photoshoprsrc, NULL },
	{ 34665, 0x08, "Exif IFD", handler_subifd, NULL },
	{ 34675, 0x08, "ICC Profile", handler_iccprofile, NULL },
	{ 34850, 0x10, "ExposureProgram", NULL, valdec_exposureprogram },
	{ 34852, 0x10, "SpectralSensitivity", NULL, NULL },
	{ 34853, 0x08, "GPS IFD", handler_subifd, NULL },
	{ 34855, 0x10, "PhotographicSensitivity/ISOSpeedRatings", NULL, NULL },
	{ 34856, 0x10, "OECF", NULL, NULL },
	{ 34857, 0x0100, "Interlace", NULL, NULL },
	{ 34858, 0x0100, "TimeZoneOffset", NULL, NULL },
	{ 34859, 0x0100, "SelfTimerMode", NULL, NULL },
	{ 34864, 0x10, "SensitivityType", NULL, NULL },
	{ 34865, 0x10, "StandardOutputSensitivity", NULL, NULL },
	{ 34866, 0x10, "RecommendedExposureIndex", NULL, NULL },
	{ 34867, 0x10, "ISOSpeed", NULL, NULL },
	{ 34868, 0x10, "ISOSpeedLatitudeyyy", NULL, NULL },
	{ 34869, 0x10, "ISOSpeedLatitudezzz", NULL, NULL },
	{ 34908, 0x00, "FaxRecvParams", NULL, NULL },
	{ 34909, 0x00, "FaxSubAddress", NULL, NULL },
	{ 34910, 0x00, "FaxSubAddress", NULL, NULL },
	{ 36864, 0x10, "ExifVersion", NULL, NULL },
	{ 36867, 0x10, "DateTimeOriginal", NULL, NULL },
	{ 36868, 0x10, "DateTimeDigitized", NULL, NULL },
	{ 37121, 0x10, "ComponentsConfiguration", NULL, valdec_componentsconfiguration },
	{ 37122, 0x10, "CompressedBitsPerPixel", NULL, NULL },
	{ 37377, 0x10, "ShutterSpeedValue", NULL, NULL },
	{ 37378, 0x10, "ApertureValue", NULL, NULL },
	{ 37379, 0x10, "BrightnessValue", NULL, NULL },
	{ 37380, 0x10, "ExposureBiasValue", NULL, NULL },
	{ 37381, 0x10, "MaxApertureValue", NULL, NULL },
	{ 37382, 0x10, "SubjectDistance", NULL, NULL },
	{ 37383, 0x10, "MeteringMode", NULL, valdec_meteringmode },
	{ 37384, 0x10, "LightSource", NULL, valdec_lightsource },
	{ 37385, 0x10, "Flash", NULL, valdec_flash },
	{ 37386, 0x10, "FocalLength", NULL, NULL },
	{ 37387, 0x0100, "FlashEnergy", NULL, NULL },
	{ 37388, 0x0100, "SpatialFrequencyResponse", NULL, NULL },
	{ 37389, 0x0100, "Noise", NULL, NULL },
	{ 37390, 0x0100, "FocalPlaneXResolution", NULL, NULL },
	{ 37391, 0x0100, "FocalPlaneYResolution", NULL, NULL },
	{ 37392, 0x0100, "FocalPlaneResolutionUnit", NULL, NULL },
	{ 37393, 0x0100, "ImageNumber", NULL, NULL },
	{ 37394, 0x0100, "SecurityClassification", NULL, NULL },
	{ 37395, 0x0100, "ImageHistory", NULL, NULL },
	{ 37396, 0x10, "SubjectArea", NULL, NULL },
	{ 37397, 0x0100, "ExposureIndex", NULL, NULL },
	{ 37398, 0x0100, "TIFF/EPStandardID", NULL, NULL },
	{ 37399, 0x0100, "SensingMethod", NULL, NULL },
	{ 37439, 0x00, "SToNits(SGI)", NULL, NULL },
	{ 37500, 0x10, "MakerNote", NULL, NULL },
	{ 37510, 0x10, "UserComment", NULL, NULL },
	{ 37520, 0x10, "SubSec", NULL, NULL },
	{ 37521, 0x10, "SubSecTimeOriginal", NULL, NULL },
	{ 37522, 0x10, "SubsecTimeDigitized", NULL, NULL },
	{ 37724, 0x00, "Photoshop ImageSourceData", NULL, NULL },
	{ 40960, 0x10, "FlashPixVersion", NULL, NULL },
	{ 40961, 0x10, "ColorSpace", NULL, valdec_exifcolorspace },
	{ 40962, 0x10, "PixelXDimension", NULL, NULL },
	{ 40963, 0x10, "PixelYDimension", NULL, NULL },
	{ 40964, 0x10, "RelatedSoundFile", NULL, NULL },
	{ 40965, 0x18, "Interoperability IFD", handler_subifd, NULL },
	{ 41483, 0x10, "FlashEnergy", NULL, NULL },
	{ 41484, 0x10, "SpatialFrequencyResponse", NULL, NULL },
	{ 41486, 0x10, "FocalPlaneXResolution", NULL, NULL },
	{ 41487, 0x10, "FocalPlaneYResolution", NULL, NULL },
	{ 41488, 0x10, "FocalPlaneResolutionUnit", NULL, valdec_resolutionunit },
	{ 41492, 0x10, "SubjectLocation", NULL, NULL },
	{ 41493, 0x10, "ExposureIndex", NULL, NULL },
	{ 41495, 0x10, "SensingMethod", NULL, valdec_sensingmethod },
	{ 41728, 0x10, "FileSource", NULL, valdec_filesource },
	{ 41729, 0x10, "SceneType", NULL, valdec_scenetype },
	{ 41730, 0x10, "CFAPattern", NULL, NULL },
	{ 41985, 0x10, "CustomRendered", NULL, valdec_customrendered },
	{ 41986, 0x10, "ExposureMode", NULL, valdec_exposuremode },
	{ 41987, 0x10, "WhiteBalance", NULL, valdec_whitebalance },
	{ 41988, 0x10, "DigitalZoomRatio", NULL, NULL },
	{ 41989, 0x10, "FocalLengthIn35mmFilm", NULL, NULL },
	{ 41990, 0x10, "SceneCaptureType", NULL, valdec_scenecapturetype },
	{ 41991, 0x10, "GainControl", NULL, valdec_gaincontrol },
	{ 41992, 0x10, "Contrast", NULL, valdec_contrast },
	{ 41993, 0x10, "Saturation", NULL, valdec_saturation },
	{ 41994, 0x10, "Sharpness", NULL, valdec_sharpness },
	{ 41995, 0x10, "DeviceSettingDescription", NULL, NULL },
	{ 41996, 0x10, "SubjectDistanceRange", NULL, valdec_subjectdistancerange },
	{ 42016, 0x10, "ImageUniqueID", NULL, NULL },
	{ 42032, 0x10, "CameraOwnerName", NULL, NULL },
	{ 42033, 0x10, "BodySerialNumber", NULL, NULL },
	{ 42034, 0x10, "LensSpecification", NULL, NULL },
	{ 42035, 0x10, "LensMake", NULL, NULL },
	{ 42036, 0x10, "LensModel", NULL, NULL },
	{ 42037, 0x10, "LensSerialNumber", NULL, NULL },
	{ 42240, 0x10, "Gamma", NULL, NULL },

	{ 50706, 0x80, "DNGVersion", NULL, NULL},
	{ 50707, 0x80, "DNGBackwardVersion", NULL, NULL},
	{ 50708, 0x80, "UniqueCameraModel", NULL, NULL},
	{ 50709, 0x80, "LocalizedCameraModel", NULL, NULL},
	{ 50710, 0x80, "CFAPlaneColor", NULL, NULL},
	{ 50711, 0x80, "CFALayout", NULL, NULL},
	{ 50712, 0x80, "LinearizationTable", NULL, NULL},
	{ 50713, 0x80, "BlackLevelRepeatDim", NULL, NULL},
	{ 50714, 0x80, "BlackLevel", NULL, NULL},
	{ 50715, 0x80, "BlackLevelDeltaH", NULL, NULL},
	{ 50716, 0x80, "BlackLevelDeltaV", NULL, NULL},
	{ 50717, 0x80, "WhiteLevel", NULL, NULL},
	{ 50718, 0x80, "DefaultScale", NULL, NULL},
	{ 50719, 0x80, "DefaultCropOrigin", NULL, NULL},
	{ 50720, 0x80, "DefaultCropSize", NULL, NULL},
	{ 50721, 0x80, "ColorMatrix1", NULL, NULL},
	{ 50722, 0x80, "ColorMatrix2", NULL, NULL},
	{ 50723, 0x80, "CameraCalibration1", NULL, NULL},
	{ 50724, 0x80, "CameraCalibration2", NULL, NULL},
	{ 50725, 0x80, "ReductionMatrix1", NULL, NULL},
	{ 50726, 0x80, "ReductionMatrix2", NULL, NULL},
	{ 50727, 0x80, "AnalogBalance", NULL, NULL},
	{ 50728, 0x80, "AsShotNeutral", NULL, NULL},
	{ 50729, 0x80, "AsShotWhiteXY", NULL, NULL},
	{ 50730, 0x80, "BaselineExposure", NULL, NULL},
	{ 50731, 0x80, "BaselineNoise", NULL, NULL},
	{ 50732, 0x80, "BaselineSharpness", NULL, NULL},
	{ 50733, 0x80, "BayerGreenSplit", NULL, NULL},
	{ 50734, 0x80, "LinearResponseLimit", NULL, NULL},
	{ 50735, 0x80, "CameraSerialNumber", NULL, NULL},
	{ 50736, 0x80, "LensInfo", NULL, NULL},
	{ 50737, 0x80, "ChromaBlurRadius", NULL, NULL},
	{ 50738, 0x80, "AntiAliasStrength", NULL, NULL},
	{ 50739, 0x80, "ShadowScale", NULL, NULL},
	{ 50740, 0x80, "DNGPrivateData", NULL, NULL},
	{ 50741, 0x80, "MakerNoteSafety", NULL, NULL},
	{ 50778, 0x80, "CalibrationIlluminant1", NULL, NULL},
	{ 50779, 0x80, "CalibrationIlluminant2", NULL, NULL},
	{ 50780, 0x80, "BestQualityScale", NULL, NULL},
	{ 50781, 0x80, "RawDataUniqueID", NULL, NULL},
	{ 50827, 0x80, "OriginalRawFileName", NULL, NULL},
	{ 50828, 0x80, "OriginalRawFileData", NULL, NULL},
	{ 50829, 0x80, "ActiveArea", NULL, NULL},
	{ 50830, 0x80, "MaskedAreas", NULL, NULL},
	{ 50831, 0x80, "AsShotICCProfile", NULL, NULL},
	{ 50832, 0x80, "AsShotPreProfileMatrix", NULL, NULL},
	{ 50833, 0x80, "CurrentICCProfile", NULL, NULL},
	{ 50834, 0x80, "CurrentPreProfileMatrix", NULL, NULL},
	{ 50879, 0x80, "ColorimetricReference", NULL, NULL},
	{ 50931, 0x80, "CameraCalibrationSignature", NULL, NULL},
	{ 50932, 0x80, "ProfileCalibrationSignature", NULL, NULL},
	{ 50933, 0x80, "ExtraCameraProfiles", NULL, NULL},
	{ 50934, 0x80, "AsShotProfileName", NULL, NULL},
	{ 50935, 0x80, "NoiseReductionApplied", NULL, NULL},
	{ 50936, 0x80, "ProfileName", NULL, NULL},
	{ 50937, 0x80, "ProfileHueSatMapDims", NULL, NULL},
	{ 50938, 0x80, "ProfileHueSatMapData1", NULL, NULL},
	{ 50939, 0x80, "ProfileHueSatMapData2", NULL, NULL},
	{ 50940, 0x80, "ProfileToneCurve", NULL, NULL},
	{ 50941, 0x80, "ProfileEmbedPolicy", NULL, valdec_profileembedpolicy},
	{ 50942, 0x80, "ProfileCopyright", NULL, NULL},
	{ 50964, 0x80, "ForwardMatrix1", NULL, NULL},
	{ 50965, 0x80, "ForwardMatrix2", NULL, NULL},
	{ 50966, 0x80, "PreviewApplicationName", NULL, NULL},
	{ 50967, 0x80, "PreviewApplicationVersion", NULL, NULL},
	{ 50968, 0x80, "PreviewSettingsName", NULL, NULL},
	{ 50969, 0x80, "PreviewSettingsDigest", NULL, NULL},
	{ 50970, 0x80, "PreviewColorSpace", NULL, valdec_dngcolorspace},
	{ 50971, 0x80, "PreviewDateTime", NULL, NULL},
	{ 50972, 0x80, "RawImageDigest", NULL, NULL},
	{ 50973, 0x80, "OriginalRawFileDigest", NULL, NULL},
	{ 50974, 0x80, "SubTileBlockSize", NULL, NULL},
	{ 50975, 0x80, "RowInterleaveFactor", NULL, NULL},
	{ 50981, 0x80, "ProfileLookTableDims", NULL, NULL},
	{ 50982, 0x80, "ProfileLookTableData", NULL, NULL},
	{ 51008, 0x80, "OpcodeList1", NULL, NULL},
	{ 51009, 0x80, "OpcodeList2", NULL, NULL},
	{ 51022, 0x80, "OpcodeList3", NULL, NULL},
	{ 51041, 0x80, "NoiseProfile", NULL, NULL},
	{ 51089, 0x80, "OriginalDefaultFinalSize", NULL, NULL},
	{ 51090, 0x80, "OriginalBestQualityFinalSize", NULL, NULL},
	{ 51091, 0x80, "OriginalDefaultCropSize", NULL, NULL},
	{ 51107, 0x80, "ProfileHueSatMapEncoding", NULL, NULL},
	{ 51108, 0x80, "ProfileLookTableEncoding", NULL, NULL},
	{ 51109, 0x80, "BaselineExposureOffset", NULL, NULL},
	{ 51110, 0x80, "DefaultBlackRender", NULL, NULL},
	{ 51111, 0x80, "NewRawImageDigest", NULL, NULL},
	{ 51112, 0x80, "RawToPreviewGain", NULL, NULL},
	{ 51113, 0x80, "CacheBlob", NULL, NULL},
	{ 51114, 0x80, "CacheVersion", NULL, NULL},
	{ 51125, 0x80, "DefaultUserCrop", NULL, NULL},

	{ 1, 0x20, "InteroperabilityIndex", NULL, NULL },
	{ 2, 0x20, "InteroperabilityVersion", NULL, NULL },

	{ 0, 0x40, "GPSVersionID", NULL, NULL },
	{ 1, 0x40, "GPSLatitudeRef", NULL, NULL },
	{ 2, 0x40, "GPSGpsLatitude", NULL, NULL },
	{ 3, 0x40, "GPSLongitudeRef", NULL, NULL },
	{ 4, 0x40, "GPSLongitude", NULL, NULL },
	{ 5, 0x40, "GPSAltitudeRef", NULL, NULL },
	{ 6, 0x40, "GPSAltitude", NULL, NULL },
	{ 7, 0x40, "GPSTimeStamp", NULL, NULL },
	{ 8, 0x40, "GPSSatellites", NULL, NULL },
	{ 9, 0x40, "GPSStatus", NULL, NULL },
	{ 10, 0x40, "GPSMeasureMode", NULL, NULL },
	{ 11, 0x40, "GPSDOP", NULL, NULL },
	{ 12, 0x40, "GPSSpeedRef", NULL, NULL },
	{ 13, 0x40, "GPSSpeed", NULL, NULL },
	{ 14, 0x40, "GPSTrackRef", NULL, NULL },
	{ 15, 0x40, "GPSTrack", NULL, NULL },
	{ 16, 0x40, "GPSImgDirectionRef", NULL, NULL },
	{ 17, 0x40, "GPSImgDirection", NULL, NULL },
	{ 18, 0x40, "GPSMapDatum", NULL, NULL },
	{ 19, 0x40, "GPSLatitudeRef", NULL, NULL },
	{ 20, 0x40, "GPSLatitude", NULL, NULL },
	{ 21, 0x40, "GPSDestLongitudeRef", NULL, NULL },
	{ 22, 0x40, "GPSDestLongitude", NULL, NULL },
	{ 23, 0x40, "GPSDestBearingRef", NULL, NULL },
	{ 24, 0x40, "GPSDestBearing", NULL, NULL },
	{ 25, 0x40, "GPSDestDistanceRef", NULL, NULL },
	{ 26, 0x40, "GPSDestDistance", NULL, NULL },
	{ 27, 0x40, "GPSProcessingMethod", NULL, NULL },
	{ 28, 0x40, "GPSAreaInformation", NULL, NULL },
	{ 29, 0x40, "GPSDateStamp", NULL, NULL },
	{ 30, 0x40, "GPSDifferential", NULL, NULL },
	{ 31, 0x40, "GPSHPositioningError", NULL, NULL }
};

// Data associated with an actual tag in an IFD in the file
struct taginfo {
	int tagnum;
	int datatype;
	int tag_known;
	de_int64 valcount;
	de_int64 val_offset;
	de_int64 unit_size;
	de_int64 total_size;
};

struct localctx_struct {
	int is_le;
	int is_bigtiff;
	int fmt;
	int host_is_le;
	int can_decode_fltpt;

	struct ifdstack_item *ifdstack;
	int ifdstack_capacity;
	int ifdstack_numused;

	de_int64 *ifdlist;
	de_int64 ifd_count;

	de_int64 ifdhdrsize;
	de_int64 ifditemsize;
	de_int64 offsetoffset;
	de_int64 offsetsize; // Number of bytes in a file offset

	de_module_params *mparams;
};

// Returns 0 if stack is empty.
static de_int64 pop_ifd(deark *c, lctx *d, int *ifdtype)
{
	de_int64 ifdpos;
	if(!d->ifdstack) return 0;
	if(d->ifdstack_numused<1) return 0;
	ifdpos = d->ifdstack[d->ifdstack_numused-1].offset;
	*ifdtype = d->ifdstack[d->ifdstack_numused-1].ifdtype;
	d->ifdstack_numused--;
	return ifdpos;
}

static void push_ifd(deark *c, lctx *d, de_int64 ifdpos, int ifdtype)
{
	int i;

	if(ifdpos==0) return;

	// Append to the IFD list (of all IFDs). This is only used for loop detection.
	if(!d->ifdlist) {
		d->ifdlist = de_malloc(c, MAX_IFDS * sizeof(de_int64));
	}
	if(d->ifd_count >= MAX_IFDS) {
		de_warn(c, "Too many TIFF IFDs\n");
		return;
	}
	for(i=0; i<d->ifd_count; i++) {
		if(ifdpos == d->ifdlist[i]) {
			de_err(c, "IFD loop detected\n");
			return;
		}
	}
	d->ifdlist[d->ifd_count] = ifdpos;
	d->ifd_count++;

	// Add to the IFD stack (of unprocessed IFDs).
	if(!d->ifdstack) {
		d->ifdstack_capacity = 200;
		d->ifdstack = de_malloc(c, d->ifdstack_capacity * sizeof(struct ifdstack_item));
		d->ifdstack_numused = 0;
	}
	if(d->ifdstack_numused >= d->ifdstack_capacity) {
		de_warn(c, "Too many TIFF IFDs\n");
		return;
	}
	d->ifdstack[d->ifdstack_numused].offset = ifdpos;
	d->ifdstack[d->ifdstack_numused].ifdtype = ifdtype;
	d->ifdstack_numused++;
}

static int size_of_data_type(int tt)
{
	switch(tt) {
	case DATATYPE_BYTE: case DATATYPE_SBYTE:
	case DATATYPE_ASCII:
	case DATATYPE_UNDEF:
		return 1;
	case DATATYPE_UINT16: case DATATYPE_SINT16:
		return 2;
	case DATATYPE_UINT32: case DATATYPE_SINT32:
	case DATATYPE_FLOAT32:
	case DATATYPE_IFD32:
		return 4;
	case DATATYPE_RATIONAL: case DATATYPE_SRATIONAL:
	case DATATYPE_FLOAT64:
	case DATATYPE_UINT64: case DATATYPE_SINT64:
	case DATATYPE_IFD64:
		return 8;
	}
	return 0;
}

static double getfloat32x(deark *c, lctx *d, dbuf *f, de_int64 pos)
{
	char buf[4];
	float val = 0.0;

	if(!d->can_decode_fltpt) return 0.0;
	dbuf_read(f, (de_byte*)buf, pos, 4);

	if(d->is_le != d->host_is_le) {
		int i;
		char tmpc;
		// Reverse order of bytes
		for(i=0; i<2; i++) {
			tmpc = buf[i]; buf[i] = buf[3-i]; buf[3-i] = tmpc;
		}
	}

	de_memcpy(&val, buf, 4);
	return (double)val;
}

static double getfloat64x(deark *c, lctx *d, dbuf *f, de_int64 pos)
{
	char buf[8];
	double val = 0.0;

	if(!d->can_decode_fltpt) return 0.0;
	dbuf_read(f, (de_byte*)buf, pos, 8);

	if(d->is_le != d->host_is_le) {
		int i;
		char tmpc;
		// Reverse order of bytes
		for(i=0; i<4; i++) {
			tmpc = buf[i]; buf[i] = buf[7-i]; buf[7-i] = tmpc;
		}
	}

	de_memcpy(&val, buf, 8);
	return val;
}

static int read_rational_as_double(deark *c, lctx *d, de_int64 pos, double *n)
{
	de_int64 num, den;

	*n = 0.0;
	num = dbuf_getui32x(c->infile, pos, d->is_le);
	den = dbuf_getui32x(c->infile, pos+4, d->is_le);
	if(den==0) return 0;
	*n = (double)num/(double)den;
	return 1;
}

static int read_srational_as_double(deark *c, lctx *d, de_int64 pos, double *n)
{
	de_int64 num, den;

	*n = 0.0;
	num = dbuf_geti32x(c->infile, pos, d->is_le);
	den = dbuf_geti32x(c->infile, pos+4, d->is_le);
	if(den==0) return 0;
	*n = (double)num/(double)den;
	return 1;
}

// FIXME: This function seems superfluous.
// It should somehow be consolidated with read_numeric_value().
static int read_tag_value_as_double(deark *c, lctx *d, const struct taginfo *tg,
	de_int64 value_index, double *n)
{
	de_int64 offs;

	*n = 0.0;
	if(value_index<0 || value_index>=tg->valcount) return 0;
	offs = tg->val_offset + value_index*tg->unit_size;

	switch(tg->datatype) {
	case DATATYPE_RATIONAL:
		return read_rational_as_double(c, d, offs, n);
	case DATATYPE_SRATIONAL:
		return read_srational_as_double(c, d, offs, n);
	case DATATYPE_FLOAT32:
		if(!d->can_decode_fltpt) return 0;
		*n = getfloat32x(c, d, c->infile, offs);
		return 1;
	case DATATYPE_FLOAT64:
		if(!d->can_decode_fltpt) return 0;
		*n = getfloat64x(c, d, c->infile, offs);
		return 1;

		// There should be no need to support other data types (like UINT32).
	}
	return 0;
}

static int read_tag_value_as_int64(deark *c, lctx *d, const struct taginfo *tg,
	de_int64 value_index, de_int64 *n)
{
	double v_dbl;
	de_int64 offs;

	*n = 0;
	if(value_index<0 || value_index>=tg->valcount) return 0;
	offs = tg->val_offset + value_index*tg->unit_size;

	switch(tg->datatype) {
	case DATATYPE_UINT16:
		*n = dbuf_getui16x(c->infile, offs, d->is_le);
		return 1;
	case DATATYPE_UINT32:
	case DATATYPE_IFD32:
		*n = dbuf_getui32x(c->infile, offs, d->is_le);
		return 1;
	case DATATYPE_BYTE:
	case DATATYPE_UNDEF:
	case DATATYPE_ASCII:
		*n = (de_int64)de_getbyte(offs);
		return 1;
	case DATATYPE_UINT64:
	case DATATYPE_IFD64:
		// TODO: Somehow support unsigned 64-bit ints that don't fit into
		// a de_int64?
		*n = dbuf_geti64x(c->infile, offs, d->is_le);
		if(*n < 0) return 0;
		return 1;
	case DATATYPE_SINT16:
		*n = dbuf_geti16x(c->infile, offs, d->is_le);
		return 1;
	case DATATYPE_SINT32:
		*n = dbuf_geti32x(c->infile, offs, d->is_le);
		return 1;
	case DATATYPE_SINT64:
		*n = dbuf_geti64x(c->infile, offs, d->is_le);
		return 1;
	case DATATYPE_SBYTE:
		*n = (de_int64)de_getbyte(offs);
		if(*n > 127) *n -= 256;
		return 1;
	case DATATYPE_RATIONAL:
	case DATATYPE_SRATIONAL:
	case DATATYPE_FLOAT32:
	case DATATYPE_FLOAT64:
		if(read_tag_value_as_double(c, d, tg, value_index, &v_dbl)) {
			*n = (de_int64)v_dbl;
			return 1;
		}
		return 0;
	}
	return 0;
}

static void format_double(dbuf *f, double val)
{
	// TODO: Formatting should be more intelligent
	dbuf_printf(f, "%.4f", val);
}

struct numeric_value {
	int isvalid;
	de_int64 val_int64;
	double val_double;
};

// Do-it-all function for reading numeric values.
// If dbglinebuf!=NULL, print a string representation of the value to it.
static void read_numeric_value(deark *c, lctx *d, const struct taginfo *tg,
	de_int64 value_index, struct numeric_value *nv, dbuf *dbglinedbuf)
{
	int ret;
	de_int64 offs;

	nv->isvalid = 0;
	nv->val_int64 = 0;
	nv->val_double = 0.0;

	// FIXME: This is recalculated in read_tag_value_as_int64.
	offs = tg->val_offset + value_index*tg->unit_size;

	switch(tg->datatype) {
	case DATATYPE_BYTE:
	case DATATYPE_SBYTE:
	case DATATYPE_UNDEF:
	case DATATYPE_ASCII:
	case DATATYPE_UINT16:
	case DATATYPE_SINT16:
	case DATATYPE_UINT32:
	case DATATYPE_SINT32:
	case DATATYPE_IFD32:
	case DATATYPE_UINT64:
	case DATATYPE_SINT64:
	case DATATYPE_IFD64:
		ret = read_tag_value_as_int64(c, d, tg, value_index, &nv->val_int64);
		nv->val_double = (double)nv->val_int64;
		nv->isvalid = ret;
		if(dbglinedbuf) {
			if(nv->isvalid)
				dbuf_printf(dbglinedbuf, "%" INT64_FMT, nv->val_int64);
			else
				dbuf_puts(dbglinedbuf, "?");
		}
		break;

	case DATATYPE_RATIONAL:
	case DATATYPE_SRATIONAL:
		{
			de_int64 num, den;

			if(tg->datatype==DATATYPE_SRATIONAL) {
				num = dbuf_geti32x(c->infile, offs, d->is_le);
				den = dbuf_geti32x(c->infile, offs+4, d->is_le);
			}
			else {
				num = dbuf_getui32x(c->infile, offs, d->is_le);
				den = dbuf_getui32x(c->infile, offs+4, d->is_le);
			}

			if(den==0) {
				nv->isvalid = 0;
				nv->val_double = 0.0;
				nv->val_int64 = 0;
				if(dbglinedbuf) {
					dbuf_printf(dbglinedbuf, "%" INT64_FMT "/%" INT64_FMT, num, den);
				}

			}
			else {
				nv->isvalid = 1;
				nv->val_double = (double)num/(double)den;
				nv->val_int64 = (de_int64)nv->val_double;
				if(dbglinedbuf) {
					format_double(dbglinedbuf, nv->val_double);
				}
			}
		}
		break;

	case DATATYPE_FLOAT32:
	case DATATYPE_FLOAT64:
		if(tg->datatype==DATATYPE_FLOAT64) {
			nv->val_double = getfloat64x(c, d, c->infile, offs);
		}
		else {
			nv->val_double = getfloat32x(c, d, c->infile, offs);
		}
		nv->val_int64 = (de_int64)nv->val_double;
		nv->isvalid = 1;
		if(dbglinedbuf) {
			format_double(dbglinedbuf, nv->val_double);
		}
		break;

	default:
		if(dbglinedbuf) {
			dbuf_puts(dbglinedbuf, "?");
		}
	}
}

static de_int64 getfpos(deark *c, lctx *d, de_int64 pos)
{
	if(d->is_bigtiff) {
		return dbuf_geti64x(c->infile, pos, d->is_le);
	}
	return dbuf_getui32x(c->infile, pos, d->is_le);
}

static void do_oldjpeg(deark *c, lctx *d, de_int64 jpegoffset, de_int64 jpeglength)
{
	const char *extension;
	unsigned int createflags;

	if(jpeglength<0) {
		// Missing JPEGInterchangeFormatLength tag. Assume it goes to the end
		// of the file.
		jpeglength = c->infile->len - jpegoffset;
	}

	// Found an embedded JPEG image or thumbnail that we can extract.
	if(d->mparams && d->mparams->codes && de_strchr(d->mparams->codes, 'E')) {
		extension = "exifthumb.jpg";
		createflags = DE_CREATEFLAG_IS_AUX;
	}
	else {
		extension = "jpg";
		// TODO: Should createflags be set to DE_CREATEFLAG_IS_AUX in some cases?
		createflags = 0;
	}
	dbuf_create_file_from_slice(c->infile, jpegoffset, jpeglength, extension, NULL, createflags);
}

static void do_leaf_metadata(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos;
	de_byte buf[4];
	de_byte segtype[40];
	de_int64 data_len;

	if(len<1) return;
	if(pos1+len > c->infile->len) return;
	de_dbg(c, "leaf metadata at %d size=%d\n", (int)pos1, (int)len);

	// This format appears to be hierarchical, but for now we only care about
	// the top level.

	pos = pos1;
	while(pos < pos1+len) {
		de_read(buf, pos, 4);
		if(de_memcmp(buf, "PKTS", 4)) {
			break;
		}
		pos+=4;

		pos+=4; // Don't know what these 4 bytes are for.

		de_read(segtype, pos, 40);
		pos+=40;

		// TODO: Is this always big-endian?
		data_len = de_getui32be(pos);
		pos+=4;

		if(!de_memcmp(segtype, "JPEG_preview_data\0", 18)) {
			de_dbg(c, "jpeg preview at %d len=%d\n", (int)pos, (int)data_len);
			dbuf_create_file_from_slice(c->infile, pos, data_len, "leafthumb.jpg", NULL, DE_CREATEFLAG_IS_AUX);
		}
		pos += data_len;
	}
}

struct int_and_str {
	de_int64 n;
	const char *s;
};

static int lookup_str_and_copy_to_buf(const struct int_and_str *items, size_t num_items,
	de_int64 n, char *buf, size_t buf_len)
{
	de_int64 i;

	for(i=0; i<(de_int64)num_items; i++) {
		if(items[i].n==n) {
			de_strlcpy(buf, items[i].s, buf_len);
			return 1;
		}
	}
	de_strlcpy(buf, "?", buf_len);
	return 0;
}

// For a dbuf being used as a string, append a NUL-terminated string.
// If the dbuf is not empty, append a comma first.
static void append_list_item(dbuf *s, const char *str)
{
	if(s->len) dbuf_writebyte(s, ',');
	dbuf_puts(s, str);
}

static int valdec_newsubfiletype(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	dbuf *s = NULL;

	if(vp->n<1) return 0;
	s = dbuf_create_membuf(c, (de_int64)vr->buf_len, 0);

	if(vp->n&0x1) {
		append_list_item(s, "reduced-res");
	}
	if(vp->n&0x2) {
		append_list_item(s, "one-page-of-many");
	}
	if(vp->n&0x4) {
		append_list_item(s, "mask");
	}
	if((vp->n & ~0x7)!=0) {
		append_list_item(s, "?");
	}

	dbuf_copy_all_to_sz(s, vr->buf, vr->buf_len);
	dbuf_close(s);
	return 1;
}

static int valdec_oldsubfiletype(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{1, "full-res"}, {2, "reduced-res"}, {3, "one-page-of-many"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_compression(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{1, "uncompressed"}, {2, "CCITTRLE"}, {3, "Fax3"}, {4, "Fax4"},
		{5, "LZW"}, {6, "OldJPEG"}, {7, "NewJPEG"}, {8, "DEFLATE"},
		{9, "JBIG"}, {10, "JBIG"},
		{32766, "NeXT 2-bit RLE"}, {32771, "CCITTRLEW"},
		{32773, "PackBits"}, {32809, "ThunderScan"},
		{32908, "PIXARFILM"}, {32909, "PIXARLOG"}, {32946, "DEFLATE"},
		{34661, "JBIG"}, {34676, "SGILOG"}, {34677, "SGILOG24"},
		{34712, "JPEG2000"}, {34715, "JBIG2"}, {34892, "Lossy JPEG(DNG)"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_photometric(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "grayscale/white-is-0"}, {1, "grayscale/black-is-0"},
		{2, "RGB"}, {3, "palette"}, {5, "CMYK"}, {6, "YCbCr"},
		{8, "CIELab"}, {9, "ICCLab"}, {10, "ITULab"},
		{32803, "CFA"}, {32844, "CIELog2L"}, {32845, "CIELog2Luv"},
		{34892, "LinearRaw"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_threshholding(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{1, "not dithered"}, {2, "ordered dither"}, {3, "error diffusion"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_fillorder(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{1, "MSB-first"}, {2, "LSB-first"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_orientation(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{1, "top-left"}, {2, "top-right"}, {3, "bottom-right"}, {4, "bottom-left"},
		{5, "left-top"}, {6, "right-top"}, {7, "right-bottom"}, {8, "left-bottom"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_planarconfiguration(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{1, "contiguous"}, {2, "separated"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_t4options(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	dbuf *s = NULL;

	if(vp->n<1) return 0;
	s = dbuf_create_membuf(c, (de_int64)vr->buf_len, 0);

	if(vp->n&0x1) {
		append_list_item(s, "2-d encoding");
	}
	if(vp->n&0x2) {
		append_list_item(s, "uncompressed mode allowed");
	}
	if(vp->n&0x4) {
		append_list_item(s, "has fill bits");
	}
	if((vp->n & ~0x7)!=0) {
		append_list_item(s, "?");
	}

	dbuf_copy_all_to_sz(s, vr->buf, vr->buf_len);
	dbuf_close(s);
	return 1;
}

static int valdec_t6options(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	dbuf *s = NULL;

	if(vp->n<1) return 0;
	s = dbuf_create_membuf(c, (de_int64)vr->buf_len, 0);

	if(vp->n&0x2) {
		append_list_item(s, "uncompressed mode allowed");
	}
	if((vp->n & ~0x2)!=0) {
		append_list_item(s, "?");
	}

	dbuf_copy_all_to_sz(s, vr->buf, vr->buf_len);
	dbuf_close(s);
	return 1;
}

static int valdec_resolutionunit(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{1, "unspecified"}, {2, "pixels/inch"}, {3, "pixels/cm"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_pagenumber(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	if(vp->idx==0) {
		de_snprintf(vr->buf, vr->buf_len, "page %d", (int)(vp->n+1));
		return 1;
	}
	if(vp->idx==1) {
		if(vp->n==0) {
			de_strlcpy(vr->buf, "of an unknown number", vr->buf_len);
		}
		else {
			de_snprintf(vr->buf, vr->buf_len, "of %d", (int)vp->n);
		}
		return 1;
	}
	return 0;
}

static int valdec_predictor(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{1, "none"}, {2, "horizontal differencing"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_extrasamples(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "unspecified"}, {1, "assoc-alpha"}, {2, "unassoc-alpha"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_sampleformat(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{1, "uint"}, {2, "signed int"}, {3, "float"}, {4, "undefined"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_jpegproc(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{1, "baseline"}, {14, "lossless+huffman"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_ycbcrpositioning(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{1, "centered"}, {2, "cosited"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_exposureprogram(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "not defined"}, {1, "manual"}, {2, "normal program"}, {3, "aperture priority"},
		{4, "shutter priority"}, {5, "creative program"}, {6, "action program"},
		{7, "portrait mode"}, {8, "landscape mode"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_componentsconfiguration(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "does not exist"}, {1, "Y"}, {2, "Cb"}, {3, "Cr"}, {4, "R"}, {5, "G"}, {6, "B"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_meteringmode(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "unknown"}, {1, "Average"}, {2, "CenterWeightedAverage"},
		{3, "Spot"}, {4, "MultiSpot"}, {5, "Pattern"}, {6, "Partial"},
		{255, "other"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_lightsource(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "unknown"}, {1, "Daylight"}, {2, "Fluorescent"},
		{3, "Tungsten"}, {4, "Flash"}, {9, "Fine weather"}, {10, "Cloudy weather"},
		{11, "Shade"}, {12, "D 5700-7100K"}, {13, "N 4600-5500K"},
		{14, "W 3800-4500K"}, {15, "WW 3250-3800K"}, {16, "L 2600-3260K"},
		{17, "Standard light A"}, {18, "Standard light B"}, {19, "Standard light C"},
		{20, "D55"}, {21, "D65"}, {22, "D75"}, {23, "D50"}, {24, "ISO studio tungsten"},
		{255, "other"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_flash(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	dbuf *s = NULL;
	de_int64 v;

	s = dbuf_create_membuf(c, (de_int64)vr->buf_len, 0);

	append_list_item(s, (vp->n&0x01)?"flash fired":"flash did not fire");

	v = (vp->n&0x06)>>1;
	if(v==0) append_list_item(s, "no strobe return detection function");
	else if(v==2) append_list_item(s, "strobe return light not detected");
	else if(v==3) append_list_item(s, "strobe return light detected");

	v = (vp->n&0x18)>>3;
	if(v==1) append_list_item(s, "compulsory flash firing");
	else if(v==2) append_list_item(s, "compulsory flash suppression");
	else if(v==3) append_list_item(s, "auto mode");

	append_list_item(s, (vp->n&0x20)?"no flash function":"flash function present");

	if(vp->n&0x40) append_list_item(s, "red eye reduction supported");

	if((vp->n & ~0x7f)!=0) {
		append_list_item(s, "?");
	}

	dbuf_copy_all_to_sz(s, vr->buf, vr->buf_len);
	dbuf_close(s);
	return 1;
}

static int valdec_exifcolorspace(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{1, "sRGB"}, {0xffff, "Uncalibrated"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_filesource(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "others"}, {1, "scanner of transparent type"},
		{2, "scanner of reflex type"}, {3, "DSC"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_scenetype(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{1, "directly photographed"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_sensingmethod(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{1, "not defined"}, {2, "1-chip color area"}, {3, "2-chip color area"},
		{4, "3-chip color area"}, {5, "color sequential area"}, {7, "trilinear"},
		{8, "color sequential linear"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_customrendered(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "normal"}, {1, "custom"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_exposuremode(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "auto"}, {1, "manual"}, {2, "auto bracket"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_whitebalance(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "auto"}, {1, "manual"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_scenecapturetype(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "standard"}, {1, "landscape"}, {2, "portrait"}, {3, "night scene"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_gaincontrol(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "none"}, {1, "low gain up"}, {2, "high gain up"},
		{3, "low gain down"}, {4, "high gain down"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_contrast(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "normal"}, {1, "soft"}, {2, "hard"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_saturation(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "normal"}, {1, "low"}, {2, "high"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_sharpness(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "normal"}, {1, "soft"}, {2, "hard"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_subjectdistancerange(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "unknown"}, {1, "macro"}, {2, "close"}, {3, "distant"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_profileembedpolicy(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "allow copying"}, {1, "embed if used"}, {2, "embed never"}, {3, "no restrictions"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static int valdec_dngcolorspace(deark *c, const struct valdec_params *vp, struct valdec_result *vr)
{
	static const struct int_and_str name_map[] = {
		{0, "unknown"}, {1, "gray gamma 2.2"}, {2, "sRGB"}, {3, "Adobe RGB"},
		{4, "ProPhoto RGB"}
	};
	lookup_str_and_copy_to_buf(name_map, ITEMS_IN_ARRAY(name_map), vp->n, vr->buf, vr->buf_len);
	return 1;
}

static void handler_colormap(deark *c, lctx *d, const struct taginfo *tg, const struct tagnuminfo *tni)
{
	de_int64 num_entries;
	de_int64 r1, g1, b1;
	de_byte r2, g2, b2;
	de_int64 i;

	num_entries = tg->valcount / 3;
	de_dbg(c, "ColorMap with %d entries\n", (int)num_entries);
	if(c->debug_level<2) return;
	for(i=0; i<num_entries; i++) {
		read_tag_value_as_int64(c, d, tg, num_entries*0 + i, &r1);
		read_tag_value_as_int64(c, d, tg, num_entries*1 + i, &g1);
		read_tag_value_as_int64(c, d, tg, num_entries*2 + i, &b1);
		r2 = (de_byte)(r1>>8);
		g2 = (de_byte)(g1>>8);
		b2 = (de_byte)(b1>>8);
		de_dbg2(c, "pal[%3d] = (%5d,%5d,%5d) -> (%3d,%3d,%3d)\n", (int)i,
			(int)r1, (int)g1, (int)b1,
			(int)r2, (int)g2, (int)b2);
	}
}

static void handler_subifd(deark *c, lctx *d, const struct taginfo *tg, const struct tagnuminfo *tni)
{
	de_int64 j;
	de_int64 tmpoffset;
	int ifdtype = IFDTYPE_NORMAL;

	if(tg->tagnum==330) ifdtype = IFDTYPE_SUBIFD;
	else if(tg->tagnum==34665) ifdtype = IFDTYPE_EXIF;
	else if(tg->tagnum==34853) ifdtype = IFDTYPE_GPS;
	else if(tg->tagnum==40965) ifdtype = IFDTYPE_EXIFINTEROP;

	for(j=0; j<tg->valcount;j++) {
		read_tag_value_as_int64(c, d, tg, j, &tmpoffset);
		de_dbg(c, "offset of %s: %d\n", tni->tagname, (int)tmpoffset);
		push_ifd(c, d, tmpoffset, ifdtype);
	}
}

static void handler_xmp(deark *c, lctx *d, const struct taginfo *tg, const struct tagnuminfo *tni)
{
	dbuf_create_file_from_slice(c->infile, tg->val_offset, tg->total_size, "xmp", NULL, DE_CREATEFLAG_IS_AUX);
}

static void handler_iptc(deark *c, lctx *d, const struct taginfo *tg, const struct tagnuminfo *tni)
{
	if(c->extract_level>=2 && tg->total_size>0) {
		dbuf_create_file_from_slice(c->infile, tg->val_offset, tg->total_size, "iptc", NULL, DE_CREATEFLAG_IS_AUX);
	}
}

static void handler_photoshoprsrc(deark *c, lctx *d, const struct taginfo *tg, const struct tagnuminfo *tni)
{
	de_dbg(c, "photoshop segment at %d datasize=%d\n", (int)tg->val_offset, (int)tg->total_size);
	de_fmtutil_handle_photoshop_rsrc(c, tg->val_offset, tg->total_size);
}

static void handler_iccprofile(deark *c, lctx *d, const struct taginfo *tg, const struct tagnuminfo *tni)
{
	dbuf_create_file_from_slice(c->infile, tg->val_offset, tg->total_size, "icc", NULL, DE_CREATEFLAG_IS_AUX);
}

#define DE_TIFF_MAX_VALUES_TO_PRINT 100

static void do_dbg_print_numeric_values(deark *c, lctx *d, const struct taginfo *tg, const struct tagnuminfo *tni,
	dbuf *dbglinedbuf)
{
	de_int64 i;
	struct valdec_params vp;
	struct valdec_result vr;
	struct numeric_value nv;

	switch(tg->datatype) {
	case DATATYPE_BYTE: case DATATYPE_SBYTE:
	case DATATYPE_UNDEF: case DATATYPE_ASCII:
	case DATATYPE_UINT16: case DATATYPE_SINT16:
	case DATATYPE_UINT32: case DATATYPE_SINT32: case DATATYPE_IFD32:
	case DATATYPE_UINT64: case DATATYPE_SINT64: case DATATYPE_IFD64:
	case DATATYPE_RATIONAL: case DATATYPE_SRATIONAL:
	case DATATYPE_FLOAT32: case DATATYPE_FLOAT64:
		break;
	default:
		return; // Not a supported numeric datatype
	}

	dbuf_puts(dbglinedbuf, " {");

	// Populate the fields of vp/vr that don't change.
	vp.d = d;
	vp.tg = tg;
	vr.buf_len = sizeof(vr.buf);

	for(i=0; i<tg->valcount && i<DE_TIFF_MAX_VALUES_TO_PRINT; i++) {
		read_numeric_value(c, d, tg, i, &nv, dbglinedbuf);

		// If possible, decode the value and print its name.
		if(nv.isvalid && tni->vdfn) {
			// Set the remaining fields of vp/vr.
			vp.idx = i;
			vp.n = nv.val_int64;
			vr.buf[0] = '\0';

			if(tni->vdfn(c, &vp, &vr)) {
				dbuf_printf(dbglinedbuf, "(=%s)", vr.buf);
			}
		}

		if(i<tg->valcount-1) {
			dbuf_puts(dbglinedbuf, ",");
		}
	}
	if(tg->valcount>DE_TIFF_MAX_VALUES_TO_PRINT) {
		dbuf_puts(dbglinedbuf, "...");
	}
	dbuf_puts(dbglinedbuf, "}");
}

static void do_dbg_print_text_values(deark *c, lctx *d, const struct taginfo *tg, const struct tagnuminfo *tni,
	dbuf *dbglinedbuf)
{
	de_ucstring *str = NULL;
	de_int64 bytes_to_read;
	char buf[DE_TIFF_MAX_VALUES_TO_PRINT+1];

	dbuf_puts(dbglinedbuf, " \"");

	str = ucstring_create(c);

	bytes_to_read = tg->total_size;
	if(bytes_to_read > DE_TIFF_MAX_VALUES_TO_PRINT)
		bytes_to_read = DE_TIFF_MAX_VALUES_TO_PRINT;

	// TODO: Some TIFF variants use UTF-8 instead of ASCII.
	dbuf_read_to_ucstring(c->infile, tg->val_offset, bytes_to_read, str,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);

	ucstring_to_printable_sz(str, buf, sizeof(buf));
	dbuf_puts(dbglinedbuf, buf);

	ucstring_destroy(str);

	dbuf_puts(dbglinedbuf, "\"");

	if(tg->valcount>DE_TIFF_MAX_VALUES_TO_PRINT) {
		dbuf_puts(dbglinedbuf, "...");
	}
}

static void do_dbg_print_values(deark *c, lctx *d, const struct taginfo *tg, const struct tagnuminfo *tni,
	dbuf *dbglinedbuf)
{
	if(c->debug_level<1) return;
	if(tni->flags&0x08) return; // Auto-display of values is suppressed for this tag.
	if(tg->valcount<1) return;

	if(tg->datatype==DATATYPE_ASCII) {
		do_dbg_print_text_values(c, d, tg, tni, dbglinedbuf);
	}
	else {
		do_dbg_print_numeric_values(c, d, tg, tni, dbglinedbuf);
	}
}

static const struct tagnuminfo *find_tagnuminfo(int tagnum, int ifdtype)
{
	de_int64 i;

	for(i=0; i<ITEMS_IN_ARRAY(tagnuminfo_arr); i++) {
		if(tagnuminfo_arr[i].flags&0x20) {
			// Skip Exif interoperability tags, unless this is an Interoperability IFD
			if(ifdtype!=IFDTYPE_EXIFINTEROP) {
				continue;
			}
		}
		if(tagnuminfo_arr[i].flags&0x40) {
			// Skip GPS tags, unless this is a GPS IFD
			if(ifdtype!=IFDTYPE_GPS) {
				continue;
			}
		}

		if(tagnuminfo_arr[i].tagnum==tagnum) {
			return &tagnuminfo_arr[i];
		}
	}
	return NULL;
}

static void process_ifd(deark *c, lctx *d, de_int64 ifdpos, int ifdtype)
{
	int num_tags;
	int i;
	de_int64 jpegoffset = 0;
	de_int64 jpeglength = -1;
	de_int64 tmpoffset;
	dbuf *dbglinedbuf = NULL;
	struct taginfo tg;
	const char *name;
	char tmpbuf[1024];
	static const struct tagnuminfo default_tni = { 0, 0x00, "?", NULL, NULL };

	switch(ifdtype) {
	case IFDTYPE_SUBIFD: name=" (SubIFD)"; break;
	case IFDTYPE_EXIF: name=" (Exif IFD)"; break;
	case IFDTYPE_EXIFINTEROP: name=" (Exif Interoperability IFD)"; break;
	case IFDTYPE_GPS: name=" (GPS IFD)"; break;
	default: name="";
	}

	de_dbg(c, "IFD at %d%s\n", (int)ifdpos, name);
	de_dbg_indent(c, 1);

	if(ifdpos >= c->infile->len || ifdpos<8) {
		de_warn(c, "Invalid IFD offset (%d)\n", (int)ifdpos);
		goto done;
	}

	if(d->is_bigtiff) {
		num_tags = (int)dbuf_geti64x(c->infile, ifdpos, d->is_le);
	}
	else {
		num_tags = (int)dbuf_getui16x(c->infile, ifdpos, d->is_le);
	}

	de_dbg(c, "number of tags: %d\n", num_tags);
	if(num_tags>200) {
		de_warn(c, "Invalid or excessive number of TIFF tags (%d)\n", num_tags);
		goto done;
	}

	// Record the next IFD in the main list.
	tmpoffset = dbuf_getui32x(c->infile, ifdpos+d->ifdhdrsize+num_tags*d->ifditemsize, d->is_le);
	if(tmpoffset!=0) {
		de_dbg(c, "offset of next IFD: %d\n", (int)tmpoffset);
		push_ifd(c, d, tmpoffset, IFDTYPE_NORMAL);
	}

	dbglinedbuf = dbuf_create_membuf(c, 1024, 0);

	for(i=0; i<num_tags; i++) {
		const struct tagnuminfo *tni;

		de_memset(&tg, 0, sizeof(struct taginfo));

		tg.tagnum = (int)dbuf_getui16x(c->infile, ifdpos+d->ifdhdrsize+i*d->ifditemsize, d->is_le);
		tg.datatype = (int)dbuf_getui16x(c->infile, ifdpos+d->ifdhdrsize+i*d->ifditemsize+2, d->is_le);
		// Not a file pos, but getfpos() does the right thing.
		tg.valcount = getfpos(c, d, ifdpos+d->ifdhdrsize+i*d->ifditemsize+4);

		tg.unit_size = size_of_data_type(tg.datatype);
		tg.total_size = tg.unit_size * tg.valcount;
		if(tg.total_size <= d->offsetsize) {
			tg.val_offset = ifdpos+d->ifdhdrsize+i*d->ifditemsize+d->offsetoffset;
		}
		else {
			tg.val_offset = getfpos(c, d, ifdpos+d->ifdhdrsize+i*d->ifditemsize+d->offsetoffset);
		}

		tni = find_tagnuminfo(tg.tagnum, ifdtype);
		if(tni) {
			tg.tag_known = 1;
		}
		else {
			tni = &default_tni; // Make sure tni is not NULL.
		}

		dbuf_empty(dbglinedbuf);
		dbuf_printf(dbglinedbuf, "tag %d (%s) ty=%d #=%d offs=%" INT64_FMT,
			tg.tagnum, tni->tagname,
			tg.datatype, (int)tg.valcount,
			tg.val_offset);

		do_dbg_print_values(c, d, &tg, tni, dbglinedbuf);

		dbuf_copy_all_to_sz(dbglinedbuf, tmpbuf, sizeof(tmpbuf));
		de_dbg(c, "%s\n", tmpbuf);
		de_dbg_indent(c, 1);

		switch(tg.tagnum) {
		case 46:
			if(d->fmt==DE_TIFFFMT_PANASONIC) {
				// Some Panasonic RAW files have a JPEG file in tag 46.
				dbuf_create_file_from_slice(c->infile, tg.val_offset, tg.total_size, "thumb.jpg", NULL, DE_CREATEFLAG_IS_AUX);
			}
			break;

		case TAG_JPEGINTERCHANGEFORMAT:
			if(tg.valcount<1) break;
			read_tag_value_as_int64(c, d, &tg, 0, &jpegoffset);
			break;

		case TAG_JPEGINTERCHANGEFORMATLENGTH:
			if(tg.valcount<1) break;
			read_tag_value_as_int64(c, d, &tg, 0, &jpeglength);
			break;

		case 34310: // Leaf MOS metadata / "PKTS"
			do_leaf_metadata(c, d, tg.val_offset, tg.total_size);
			break;

		default:
			if(tni->hfn) {
				tni->hfn(c, d, &tg, tni);
			}
		}

		de_dbg_indent(c, -1);
	}

	if(jpegoffset>0 && jpeglength!=0) {
		do_oldjpeg(c, d, jpegoffset, jpeglength);
	}

done:
	de_dbg_indent(c, -1);
	dbuf_close(dbglinedbuf);
}

static void do_tiff(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 ifdoffs;

	pos = 0;
	de_dbg(c, "TIFF file header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	de_dbg(c, "byte order: %s-endian\n", d->is_le?"little":"big");

	// Skip over the signature
	if(d->is_bigtiff) {
		pos += 8;
	}
	else {
		pos += 4;
	}

	// Read the first IFD offset
	ifdoffs = getfpos(c, d, pos);
	de_dbg(c, "offset of first IFD: %d\n", (int)ifdoffs);
	push_ifd(c, d, ifdoffs, IFDTYPE_NORMAL);

	de_dbg_indent(c, -1);

	// Process IFDs until we run out of them.
	while(1) {
		int ifdtype = IFDTYPE_NORMAL;
		ifdoffs = pop_ifd(c, d, &ifdtype);
		if(ifdoffs==0) break;
		process_ifd(c, d, ifdoffs, ifdtype);
	}
}

static int de_identify_tiff_internal(deark *c, int *is_le)
{
	de_int64 byte_order_sig;
	de_int64 magic;
	int fmt = 0;

	byte_order_sig = de_getui16be(0);
	*is_le = (byte_order_sig == 0x4d4d) ? 0 : 1;

	if(*is_le)
		magic = de_getui16le(2);
	else
		magic = de_getui16be(2);

	if(byte_order_sig==0x4550 && magic==0x002a) {
		fmt = DE_TIFFFMT_MDI;
	}
	else if(byte_order_sig==0x4d4d || byte_order_sig==0x4949) {

		switch(magic) {
		case 0x002a: // Standard TIFF
			fmt = DE_TIFFFMT_TIFF;
			break;
		case 0x002b:
			fmt = DE_TIFFFMT_BIGTIFF;
			break;
		case 0x0055:
			fmt = DE_TIFFFMT_PANASONIC;
			break;

		//case 0x01bc: // JPEG-XR
		//case 0x314e: // NIFF

		case 0x4352:
			fmt = DE_TIFFFMT_DCP;
			break;
		case 0x4f52:
		case 0x5352:
			fmt = DE_TIFFFMT_ORF;
			break;
		}
	}

	return fmt;
}

static void init_fltpt_decoder(deark *c, lctx *d)
{
	unsigned int x = 1;
	char b = 0;

	if(sizeof(float)!=4 || sizeof(double)!=8) return;
	d->can_decode_fltpt = 1;

	memcpy(&b, &x, 1);
	if(b!=0) d->host_is_le = 1;
}

static void de_run_tiff(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	if(c->module_nesting_level>1) de_dbg2(c, "in tiff module\n");
	d = de_malloc(c, sizeof(lctx));

	d->mparams = mparams;

	d->fmt = de_identify_tiff_internal(c, &d->is_le);

	switch(d->fmt) {
	case DE_TIFFFMT_TIFF:
		de_declare_fmt(c, "TIFF");
		break;
	case DE_TIFFFMT_BIGTIFF:
		de_declare_fmt(c, "BigTIFF");
		d->is_bigtiff = 1;
		break;
	case DE_TIFFFMT_PANASONIC:
		de_declare_fmt(c, "Panasonic RAW/RW2");
		break;
	case DE_TIFFFMT_ORF:
		de_declare_fmt(c, "Olympus RAW");
		break;
	case DE_TIFFFMT_DCP:
		de_declare_fmt(c, "DNG Camera Profile");
		break;
	case DE_TIFFFMT_MDI:
		de_declare_fmt(c, "MDI");
		break;
	}

	if(d->fmt==0) {
		de_warn(c, "This is not a known/supported TIFF or TIFF-like format.\n");
	}

	if(d->is_bigtiff) {
		d->ifdhdrsize = 8;
		d->ifditemsize = 20;
		d->offsetoffset = 12;
		d->offsetsize = 8;
	}
	else {
		d->ifdhdrsize = 2;
		d->ifditemsize = 12;
		d->offsetoffset = 8;
		d->offsetsize = 4;
	}

	init_fltpt_decoder(c, d);

	do_tiff(c, d);

	if(d) {
		de_free(c, d->ifdstack);
		de_free(c, d->ifdlist);
		de_free(c, d);
	}
}

static int de_identify_tiff(deark *c)
{
	int fmt;
	int is_le;

	fmt = de_identify_tiff_internal(c, &is_le);
	if(fmt!=0) return 100;
	return 0;
}

void de_module_tiff(deark *c, struct deark_module_info *mi)
{
	mi->id = "tiff";
	mi->desc = "TIFF image (resources only)";
	mi->run_fn = de_run_tiff;
	mi->identify_fn = de_identify_tiff;
}
