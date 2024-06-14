#ifdef DSETUP_EXPORTS
#define DSETUP_API __declspec(dllexport)
#else
#define DSETUP_API __declspec(dllimport)
#endif

class DSETUP_API Cdsetup
{
public:
	Cdsetup(void);
};

extern DSETUP_API int ndsetup;

DSETUP_API int fndsetup(void);
