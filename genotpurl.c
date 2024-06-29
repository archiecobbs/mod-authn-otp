/*
 * Generates URLs for Google Authenticator.
 */

#include "otpdefs.h"

static void urlencode(FILE *fp, const char *s);
static void print_key(FILE *fp, const unsigned char *key, u_int len, int base32);
static void usage(void);

#define PROG_NAME               "genotpurl"

#define DEFAULT_COUNTER         0
#define DEFAULT_KEYLEN          10
#define MIN_KEYLEN              4
#define DEFAULT_NUM_DIGITS      6
#define DEFAULT_PERIOD          30

#define RANDOM_FILE             "/dev/urandom"

int
main(int argc, char **argv)
{
#ifdef DEFAULT_ISSUER
    const char *issuer = DEFAULT_ISSUER;
#else
    const char *issuer = NULL;
#endif
#ifdef DEFAULT_LABEL
    const char *label = DEFAULT_LABEL;
#else
    const char *label = NULL;
#endif
    unsigned int period = DEFAULT_PERIOD;
    unsigned int counter = DEFAULT_COUNTER;
    unsigned int num_digits = 6;
    int time_based = 1;
    unsigned char *key = NULL;
    int keylen = DEFAULT_KEYLEN;
    FILE *fp;
    int i, j;
    unsigned int b;

    // Parse command line
    while ((i = getopt(argc, argv, "c:d:iI:k:K:L:p:")) != -1) {
        switch (i) {
        case 'c':
            counter = atoi(optarg);
            break;
        case 'd':
            num_digits = atoi(optarg);
            break;
        case 'i':
            time_based = 0;
            break;
        case 'I':
            issuer = optarg;
            break;
        case 'k':
            if (strlen(optarg) % 2 != 0)
                errx(1, "invalid hex key `%s': odd number of digits", optarg);
            if ((key = malloc((keylen = strlen(optarg) / 2))) == NULL)
                err(1, "malloc");
            for (j = 0; j < keylen; j++) {
                if (sscanf(optarg + 2 * j, "%2x", &b) != 1)
                    errx(1, "invalid hex key `%s': can't parse", optarg);
                key[j] = b & 0xff;
            }
            break;
        case 'K':
            if (key != NULL)
                break;
            keylen = atoi(optarg);
            if (keylen < MIN_KEYLEN)
                errx(1, "invalid key length `%s'", optarg);
            break;
        case 'L':
            label = optarg;
            break;
        case 'p':
            period = atoi(optarg);
            break;
        case '?':
        default:
            usage();
            exit(1);
        }
    }
    argv += optind;
    argc -= optind;
    switch (argc) {
    case 0:
        break;
    default:
        usage();
        exit(1);
    }

    // Sanity check
    if (time_based && counter != DEFAULT_COUNTER)
        errx(1, "use of `-c' flag is invalid with time-based tokens");
    if (!time_based && period != DEFAULT_PERIOD)
        errx(1, "use of `-p' flag is invalid with time-based tokens");
    if (label == NULL)
        errx(1, "label required; use `-L' flag");
    if (issuer == NULL)
        errx(1, "issuer required; use `-I' flag");
    if (strchr(issuer, ':') != NULL || strchr(label, ':') != NULL)
        errx(1, "issuer and label must not contain the colon character");
    if (time_based && period != DEFAULT_PERIOD)
        errx(1, "google authenticator does not support time periods other than %d seconds", DEFAULT_PERIOD);
    if (num_digits != DEFAULT_NUM_DIGITS)
        errx(1, "google authenticator does not support number digits other than %d", DEFAULT_NUM_DIGITS);

    // Generate key (if not supplied)
    if (key == NULL) {
        if ((key = malloc((keylen))) == NULL)
            err(1, "malloc");
        if ((fp = fopen(RANDOM_FILE, "r")) == NULL)
            err(1, "%s", RANDOM_FILE);
        if (fread(key, 1, keylen, fp) != keylen)
            err(1, "%s", RANDOM_FILE);
        fclose(fp);
        fprintf(stderr, "generated key (hex): ");
        print_key(stderr, key, keylen, 0);
        fprintf(stderr, "\n");
    }

    // Output URL
    printf("otpauth://%s/", time_based ? "totp" : "hotp");
    urlencode(stdout, issuer);
    printf(":");
    urlencode(stdout, label);
    printf("?issuer=");
    urlencode(stdout, issuer);
    printf("&secret=");
    print_key(stdout, key, keylen, 1);
    if (num_digits != DEFAULT_NUM_DIGITS)
        printf("&digits=%u", num_digits);
    if (!time_based)
        printf("&counter=%u", counter);
    else if (period != DEFAULT_PERIOD)
        printf("&period=%u", period);
    printf("\n");

    // Done
    return 0;
}

static void
urlencode(FILE *fp, const char *s)
{
    while (*s != '\0') {
        if (isalnum(*s))
            fprintf(fp, "%c", *s);
        else
            fprintf(fp, "%%%02x", *s & 0xff);
        s++;
    }
}

static void
print_key(FILE *fp, const unsigned char *key, u_int len, int base32)
{
    unsigned char *buf;
    u_int buflen;
    int i;

    if (base32) {
        buflen = ((len + 4) / 5) * 8;
        if ((buf = malloc(buflen + 1)) == NULL)
            err(1, "malloc");
        buf[buflen] = 0;
        base32_encode(key, len, buf);
        assert(buf[buflen] == 0 && (buflen == 0 || buf[buflen - 1] != 0));
        for (i = 0; i < buflen; i++)
            fputc(buf[i], fp);
        free(buf);
    } else {
        for (i = 0; i < len; i++)
            fprintf(fp, "%02x", key[i] & 0xff);
    }
}

static void
usage(void)
{
    fprintf(stderr, "Usage: genotpurl [-i]");
#ifdef DEFAULT_ISSUER
    fprintf(stderr, " [-I issuer]");
#else
    fprintf(stderr, " -I issuer");
#endif
#ifdef DEFAULT_LABEL
    fprintf(stderr, " [-L label]");
#else
    fprintf(stderr, " -L label");
#endif
    fprintf(stderr, " [-c counter] [-d num-digits] [-p period] [-k key | -K keylength]\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c\tInitial counter value (default %d)\n", DEFAULT_COUNTER);
    fprintf(stderr, "  -d\tNumber of digits (default %d)\n", DEFAULT_NUM_DIGITS);
    fprintf(stderr, "  -i\tInterval-based instead of time-based\n");
#ifdef DEFAULT_ISSUER
    fprintf(stderr, "  -I\tSpecify issuer (default \"%s\")\n", DEFAULT_ISSUER);
#else
    fprintf(stderr, "  -I\tSpecify issuer (REQUIRED)\n");
#endif
    fprintf(stderr, "  -p\tTime period in seconds (default %d)\n", DEFAULT_PERIOD);
    fprintf(stderr, "  -k\tSpecify hex key (default auto-generate and report)\n");
    fprintf(stderr, "  -K\tSpecify a key length if key is to be generated (default: %d)\n", DEFAULT_KEYLEN);
#ifdef DEFAULT_LABEL
    fprintf(stderr, "  -L\tSpecify label (default \"%s\")\n", DEFAULT_LABEL);
#else
    fprintf(stderr, "  -L\tSpecify label (REQUIRED)\n");
#endif
}
