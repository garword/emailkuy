import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import Link from "next/link";
import { LanguageSelector } from "@/components/language-selector";
import { Language, t } from "@/lib/translations";
import { 
  Mail, 
  Globe, 
  Plus, 
  Trash2, 
  RefreshCw, 
  Copy, 
  Check, 
  AlertCircle,
  Sparkles,
  Shield,
  Clock,
  Zap,
  Settings,
  LogOut
} from "lucide-react";
import { toast } from "sonner";

interface CloudflareZone {
  id: string;
  name: string;
  status: string;
}

interface EmailRouting {
  id: string;
  zoneId: string;
  zoneName: string;
  aliasPart: string;
  fullEmail: string;
  ruleId: string;
  destination: string;
  isActive: boolean;
  createdAt: string;
}

const indonesianFirstNames = [
  "budi", "siti", "agus", "dewi", "eko", "rina", "fajar", "dian", "rizky", "nur",
  "andi", "maya", "hendra", "sari", "joko", "putri", "bayu", "fitri", "dimas", "angga",
  "wati", "bambang", "yuni", "doni", "indah", "reza", "kartika", "ahmad", "susanti", "pratama"
];

const indonesianLastNames = [
  "santoso", "pratama", "wijaya", "kusuma", "hidayat", "saputra", "wulandari", "nugroho",
  "siregar", "nasution", "putra", "dewi", "pertiwi", "permata", "cahyono", "rahman",
  "hakim", "fauzi", "subekti", "marlina", "handoko", "susilo", "fitriani", "rahmawati"
];

// Daftar email tujuan yang tersedia (akan di-load dari API config)
const defaultPredefinedEmails = [
  "manulsinul99@gmail.com",
];

export default function EmailRoutingManager() {
  const router = useRouter();
  const [language, setLanguage] = useState<Language>("id");
  const [zones, setZones] = useState<CloudflareZone[]>([]);
  const [selectedZone, setSelectedZone] = useState<string>("");
  const [emailList, setEmailList] = useState<EmailRouting[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isAutoMode, setIsAutoMode] = useState(true);
  const [manualAlias, setManualAlias] = useState("");
  const [destinationEmail, setDestinationEmail] = useState("");
  const [customEmail, setCustomEmail] = useState("");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [darkMode, setDarkMode] = useState(false);
  const [configStatus, setConfigStatus] = useState<"checking" | "configured" | "not-configured">("checking");
  const [predefinedEmails, setPredefinedEmails] = useState<string[]>(defaultPredefinedEmails);
  const [userInfo, setUserInfo] = useState<any>(null);

  // Load zones on mount
  useEffect(() => {
    loadUserInfo();
    loadZones();
    loadEmailList();
    checkConfig();
    loadDestinationEmails();
    
    // Load language preference
    const savedLang = localStorage.getItem("language") as Language;
    if (savedLang) setLanguage(savedLang);
    
    // Check for dark mode preference
    const isDark = localStorage.getItem('darkMode') === 'true';
    setDarkMode(isDark);
    if (isDark) {
      document.documentElement.classList.add('dark');
    }

    // Setup interval untuk check config setiap 5 detik
    const configCheckInterval = setInterval(checkConfig, 5000);
    return () => clearInterval(configCheckInterval);
  }, []);

  const loadUserInfo = () => {
    const savedUserInfo = localStorage.getItem("user_info");
    if (savedUserInfo) {
      try {
        setUserInfo(JSON.parse(savedUserInfo));
      } catch (error) {
        console.error("Failed to parse user info:", error);
      }
    }
  };

  const checkConfig = async () => {
    try {
      const response = await fetch('/api/cloudflare/config');
      const data = await response.json();
      
      if (data.success && data.config && data.config._full) {
        setConfigStatus("configured");
      } else {
        setConfigStatus("not-configured");
      }
    } catch (error) {
      setConfigStatus("not-configured");
    }
  };

  // Auto-refresh zones ketika config berubah menjadi configured
  useEffect(() => {
    if (configStatus === "configured" && zones.length === 0) {
      loadZones();
    }
  }, [configStatus]);

  const loadZones = async () => {
    try {
      setIsLoading(true);
      const response = await fetch('/api/cloudflare/zones');
      const data = await response.json();
      
      if (data.success) {
        setZones(data.zones);
        if (data.zones.length > 0) {
          setSelectedZone(data.zones[0].id);
        }
        if (configStatus !== "configured") {
          setConfigStatus("configured");
        }
      } else {
        toast.error(data.error || t("Gagal memuat domains", language));
        setConfigStatus("not-configured");
      }
    } catch (error) {
      toast.error(t("Gagal memuat domains", language));
      setConfigStatus("not-configured");
      console.error(error);
    } finally {
      setIsLoading(false);
    }
  };

  const loadEmailList = async () => {
    try {
      const response = await fetch('/api/email-routing');
      const data = await response.json();
      
      if (data.success) {
        setEmailList(data.emails);
      }
    } catch (error) {
      console.error("Failed to load email list:", error);
    }
  };

  const loadDestinationEmails = async () => {
    try {
      const response = await fetch('/api/cloudflare/config');
      const data = await response.json();
      
      if (data.success && data.config && data.config.destinationEmails) {
        const emails = Array.isArray(data.config.destinationEmails) 
          ? data.config.destinationEmails 
          : JSON.parse(data.config.destinationEmails || '[]');
        setPredefinedEmails(emails.length > 0 ? emails : defaultPredefinedEmails);
      }
    } catch (error) {
      console.error("Failed to load destination emails:", error);
      setPredefinedEmails(defaultPredefinedEmails);
    }
  };

  const generateIndonesianName = () => {
    const firstName = indonesianFirstNames[Math.floor(Math.random() * indonesianFirstNames.length)];
    const lastName = indonesianLastNames[Math.floor(Math.random() * indonesianLastNames.length)];
    const randomSuffix = Math.random().toString(36).substring(2, 5);
    return `${firstName}${lastName}${randomSuffix}`;
  };

  const createEmailRouting = async () => {
    const finalDestinationEmail = destinationEmail === "custom" ? customEmail : destinationEmail;
    
    if (!selectedZone || !finalDestinationEmail) {
      toast.error(t("Pilih domain dan masukkan email tujuan", language));
      return;
    }

    const aliasPart = isAutoMode ? generateIndonesianName() : manualAlias;
    if (!aliasPart) {
      toast.error(t("Masukkan alias email", language));
      return;
    }

    try {
      setIsLoading(true);
      const response = await fetch('/api/email-routing', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          zoneId: selectedZone,
          aliasPart,
          destinationEmail: finalDestinationEmail
        })
      });

      const data = await response.json();
      
      if (data.success) {
        toast.success(t("Email routing berhasil dibuat!", language));
        setManualAlias("");
        setCustomEmail("");
        setDestinationEmail("");
        loadEmailList();
      } else {
        toast.error(t("Gagal membuat email routing:", language) + " " + data.error);
      }
    } catch (error) {
      toast.error(t("Gagal membuat email routing", language));
      console.error(error);
    } finally {
      setIsLoading(false);
    }
  };

  const deleteEmailRouting = async (id: string, ruleId: string) => {
    try {
      setIsLoading(true);
      const response = await fetch(`/api/email-routing/${id}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ruleId })
      });

      const data = await response.json();
      
      if (data.success) {
        toast.success(t("Email routing berhasil dihapus!", language));
        loadEmailList();
      } else {
        toast.error(t("Gagal menghapus email routing:", language) + " " + data.error);
      }
    } catch (error) {
      toast.error(t("Gagal menghapus email routing", language));
      console.error(error);
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const toggleDarkMode = () => {
    const newDarkMode = !darkMode;
    setDarkMode(newDarkMode);
    localStorage.setItem('darkMode', newDarkMode.toString());
    if (newDarkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  };

  const handleLanguageChange = (lang: Language) => {
    setLanguage(lang);
    localStorage.setItem("language", lang);
  };

  const handleLogout = async () => {
    try {
      const response = await fetch('/api/auth/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const data = await response.json();

      if (data.success) {
        // Clear local storage
        localStorage.removeItem("auth_token");
        localStorage.removeItem("user_info");
        localStorage.removeItem("remember_me");
        
        // Clear cookie
        document.cookie = "auth_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
        
        toast.success(t("Logout berhasil!", language));
        router.push("/auth/login");
      } else {
        toast.error(data.error || t("Logout gagal", language));
      }
    } catch (error) {
      console.error("Logout error:", error);
      toast.error(t("Terjadi kesalahan, silakan coba lagi", language));
    }
  };

  const selectedZoneData = zones.find(z => z.id === selectedZone);

  return (
    <div className={`min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800 transition-colors duration-300`}>
      {/* Header */}
      <div className="bg-white dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700">
        <div className="container mx-auto px-3 sm:px-4 py-2 sm:py-3">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
            <div className="flex items-center space-x-2 flex-1">
              <div className="p-1.5 bg-blue-500 rounded-lg flex-shrink-0">
                <Mail className="w-4 sm:w-5 h-4 sm:h-5 text-white" />
              </div>
              <div className="min-w-0">
                <h1 className="text-base sm:text-xl font-bold text-slate-900 dark:text-white truncate">{t("Email Routing Manager", language)}</h1>
                <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 hidden sm:block truncate">{t("Kelola alamat email Cloudflare Anda dengan mudah", language)}</p>
              </div>
            </div>
            <div className="flex items-center gap-1 w-full sm:w-auto">
              <LanguageSelector 
                currentLanguage={language}
                onLanguageChange={handleLanguageChange}
              />
              <Link href="/dashboard/config" className="flex-1 sm:flex-none">
                <Button
                  variant="outline"
                  size="sm"
                  className="w-full sm:w-auto text-xs sm:text-sm h-8 sm:h-9"
                >
                  <Settings className="w-3 sm:w-4 h-3 sm:h-4 mr-1" />
                  <span className="hidden sm:inline">{t("API Config", language)}</span>
                  <span className="sm:hidden">{t("Config", language)}</span>
                </Button>
              </Link>
              <Button
                variant="outline"
                size="sm"
                onClick={toggleDarkMode}
              >
                {darkMode ? "☀️" : "🌙"}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={handleLogout}
                title={t("Logout", language)}
              >
                <LogOut className="w-3 sm:w-4 h-3 sm:h-4" />
              </Button>
            </div>
          </div>
        </div>
      </div>

      <div className="container mx-auto px-3 sm:px-4 py-3 sm:py-6">
        {configStatus === "not-configured" && (
          <Alert variant="destructive" className="mb-3 sm:mb-4 border-red-300 bg-red-50 dark:bg-red-900/20">
            <AlertCircle className="h-4 w-4 flex-shrink-0" />
            <AlertDescription className="text-xs sm:text-sm">
              <span className="font-semibold">⚠️ {t("Cloudflare API belum dikonfigurasi!", language)}</span> 
              <span className="block sm:inline ml-0 sm:ml-2 mt-2 sm:mt-0">{t("Silakan klik tombol", language)} <strong>{t("API Config", language)}</strong> {t("di header untuk setup API key terlebih dahulu.", language)}</span>
            </AlertDescription>
          </Alert>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 sm:gap-4">
          {/* Main Content */}
          <div className="lg:col-span-2 space-y-4">
            {/* Create Email Routing Card */}
            <Card className="bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700">
              <CardHeader className="p-3 sm:p-4">
                <div className="flex items-center space-x-2">
                  <Plus className="w-4 sm:w-5 h-4 sm:h-5 text-blue-500 flex-shrink-0" />
                  <CardTitle className="text-base sm:text-lg text-slate-900 dark:text-white">{t("Buat Email Routing Baru", language)}</CardTitle>
                </div>
                <CardDescription className="text-xs sm:text-sm text-slate-600 dark:text-slate-400">
                  {t("Buat alamat email baru yang diteruskan ke email tujuan Anda", language)}
                </CardDescription>
              </CardHeader>
              <CardContent className="p-3 sm:p-4 space-y-3 sm:space-y-4">
                {/* Zone Selection */}
                <div className="space-y-1.5">
                  <Label htmlFor="zone" className="text-xs sm:text-sm font-medium text-slate-700 dark:text-slate-300">
                    <Globe className="w-3 sm:w-4 h-3 sm:h-4 inline mr-1" />
                    {t("Domain", language)}
                  </Label>
                  <Select value={selectedZone} onValueChange={setSelectedZone} disabled={isLoading}>
                    <SelectTrigger className="w-full text-xs sm:text-sm h-8 sm:h-9">
                      <SelectValue placeholder={t("Pilih domain...", language)} />
                    </SelectTrigger>
                    <SelectContent>
                      {zones.map((zone) => (
                        <SelectItem key={zone.id} value={zone.id}>
                          {zone.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                {/* Email Mode Selection */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label className="text-xs sm:text-sm font-medium text-slate-700 dark:text-slate-300">
                      {t("Mode Pembuatan Email", language)}
                    </Label>
                    <Switch
                      checked={isAutoMode}
                      onCheckedChange={setIsAutoMode}
                      disabled={isLoading}
                    />
                  </div>
                  
                  <div className="flex items-center space-x-2 text-xs sm:text-sm text-slate-600 dark:text-slate-400">
                    {isAutoMode ? (
                      <>
                        <Sparkles className="w-3 sm:w-4 h-3 sm:h-4 text-blue-500 flex-shrink-0" />
                        <span>{t("Otomatis (Nama Indonesia + Random)", language)}</span>
                      </>
                    ) : (
                      <>
                        <Mail className="w-3 sm:w-4 h-3 sm:h-4 text-green-500 flex-shrink-0" />
                        <span>{t("Manual (Custom Alias)", language)}</span>
                      </>
                    )}
                  </div>

                  {isAutoMode ? (
                    <div className="p-2.5 sm:p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
                      <div className="flex items-center space-x-2 mb-1.5">
                        <Sparkles className="w-3 sm:w-4 h-3 sm:h-4 text-blue-500 flex-shrink-0" />
                        <span className="text-xs sm:text-sm font-medium text-blue-700 dark:text-blue-300">
                          {t("Preview Nama Otomatis", language)}
                        </span>
                      </div>
                      <div className="text-xs text-blue-600 dark:text-blue-400 space-y-0.5">
                        <p>• budisantoso8x9@{selectedZoneData?.name || 'domain.com'}</p>
                        <p>• sitipratama99a@{selectedZoneData?.name || 'domain.com'}</p>
                        <p>• aguswijaya2b3@{selectedZoneData?.name || 'domain.com'}</p>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-1.5">
                      <Label htmlFor="alias" className="text-xs sm:text-sm font-medium text-slate-700 dark:text-slate-300">
                        {t("Alias Email", language)}
                      </Label>
                      <Input
                        id="alias"
                        type="text"
                        placeholder={t("contoh: support", language)}
                        value={manualAlias}
                        onChange={(e) => setManualAlias(e.target.value)}
                        disabled={isLoading}
                        className="w-full text-xs sm:text-sm h-8 sm:h-9"
                      />
                    </div>
                  )}
                </div>

                {/* Destination Email */}
                <div className="space-y-1.5">
                  <Label htmlFor="destination" className="text-xs sm:text-sm font-medium text-slate-700 dark:text-slate-300">
                    {t("Email Tujuan", language)}
                  </Label>
                  <Select 
                    value={destinationEmail === customEmail && customEmail ? "custom" : destinationEmail} 
                    onValueChange={(value) => {
                      if (value === "custom") {
                        setDestinationEmail("custom");
                      } else {
                        setDestinationEmail(value);
                        setCustomEmail("");
                      }
                    }} 
                    disabled={isLoading}
                  >
                    <SelectTrigger className="w-full text-xs sm:text-sm h-8 sm:h-9">
                      <SelectValue placeholder={t("Pilih email tujuan...", language)} />
                    </SelectTrigger>
                    <SelectContent>
                      {predefinedEmails.map((email) => (
                        <SelectItem key={email} value={email}>
                          {email}
                        </SelectItem>
                      ))}
                      <Separator className="my-2" />
                      <SelectItem value="custom">📝 {t("Masukkan Email Custom", language)}</SelectItem>
                    </SelectContent>
                  </Select>
                  
                  {destinationEmail === "custom" && (
                    <Input
                      type="email"
                      placeholder="email@example.com"
                      value={customEmail}
                      onChange={(e) => setCustomEmail(e.target.value)}
                      disabled={isLoading}
                      className="w-full mt-1.5 text-xs sm:text-sm h-8 sm:h-9"
                    />
                  )}
                </div>

                {/* Quick Actions */}
                <div className="space-y-1.5">
                  <Label className="text-xs sm:text-sm font-medium text-slate-700 dark:text-slate-300">
                    {t("Quick Actions", language)}
                  </Label>
                  <div className="grid grid-cols-2 gap-1.5">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={loadZones}
                      disabled={isLoading}
                      className="justify-start text-xs sm:text-sm h-8 sm:h-9 px-2 sm:px-3"
                    >
                      <RefreshCw className={`w-2.5 sm:w-3 h-2.5 sm:h-3 mr-1 flex-shrink-0 ${isLoading ? 'animate-spin' : ''}`} />
                      <span className="text-xs sm:text-sm truncate">{t("Refresh Domains", language)}</span>
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setManualAlias(generateIndonesianName());
                        setIsAutoMode(false);
                      }}
                      className="justify-start text-xs sm:text-sm h-8 sm:h-9 px-2 sm:px-3"
                    >
                      <Sparkles className="w-2.5 sm:w-3 h-2.5 sm:h-3 mr-1 flex-shrink-0" />
                      <span className="text-xs sm:text-sm truncate">{t("Generate Name", language)}</span>
                    </Button>
                  </div>
                </div>

                <Button 
                  onClick={createEmailRouting} 
                  disabled={isLoading || !selectedZone || (destinationEmail === "custom" ? !customEmail : !destinationEmail)}
                  className="w-full bg-blue-500 hover:bg-blue-600 text-white text-xs sm:text-sm h-9 sm:h-10"
                >
                  {isLoading ? (
                    <>
                      <RefreshCw className="w-3 sm:w-4 h-3 sm:h-4 mr-1 sm:mr-2 animate-spin flex-shrink-0" />
                      {t("Memproses...", language)}
                    </>
                  ) : (
                    <>
                      <Plus className="w-3 sm:w-4 h-3 sm:h-4 mr-1 sm:mr-2 flex-shrink-0" />
                      {t("Buat Email Routing", language)}
                    </>
                  )}
                </Button>
              </CardContent>
            </Card>

            {/* Email List */}
            <Card className="bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700">
              <CardHeader className="p-3 sm:p-4">
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                  <div className="flex items-center space-x-2">
                    <Mail className="w-4 sm:w-5 h-4 sm:h-5 text-green-500 flex-shrink-0" />
                    <CardTitle className="text-base sm:text-lg text-slate-900 dark:text-white">{t("Daftar Email Routing", language)}</CardTitle>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={loadEmailList}
                    disabled={isLoading}
                    className="w-full sm:w-auto text-xs sm:text-sm"
                  >
                    <RefreshCw className={`w-3 sm:w-4 h-3 sm:h-4 ${isLoading ? 'animate-spin' : ''}`} />
                  </Button>
                </div>
                <CardDescription className="text-xs sm:text-sm text-slate-600 dark:text-slate-400">
                  {t("Kelola semua alamat email routing yang telah dibuat", language)}
                </CardDescription>
              </CardHeader>
              <CardContent className="p-3 sm:p-6">
                {emailList.length === 0 ? (
                  <div className="text-center py-8">
                    <Mail className="w-8 sm:w-12 h-8 sm:h-12 text-slate-300 dark:text-slate-600 mx-auto mb-4" />
                    <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400">{t("Belum ada email routing yang dibuat", language)}</p>
                  </div>
                ) : (
                  <div className="space-y-2 sm:space-y-3">
                    {emailList.map((email) => (
                      <div
                        key={email.id}
                        className="p-2.5 sm:p-3 bg-slate-50 dark:bg-slate-700 rounded-lg border border-slate-200 dark:border-slate-600"
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center space-x-2 mb-1 flex-wrap">
                              <h3 className="font-medium text-xs sm:text-sm text-slate-900 dark:text-white truncate">
                                {email.fullEmail}
                              </h3>
                              <Badge variant={email.isActive ? "default" : "secondary"} className="text-xs">
                                {email.isActive ? t("Active", language) : t("Inactive", language)}
                              </Badge>
                            </div>
                            <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 mb-1 truncate">
                              → {email.destination}
                            </p>
                            <div className="flex items-center space-x-3 flex-wrap text-xs text-slate-500 dark:text-slate-400">
                              <span className="flex items-center space-x-1">
                                <Globe className="w-2.5 sm:w-3 h-2.5 sm:h-3 flex-shrink-0" />
                                <span className="truncate">{email.zoneName}</span>
                              </span>
                              <span className="flex items-center space-x-1">
                                <Clock className="w-2.5 sm:w-3 h-2.5 sm:h-3 flex-shrink-0" />
                                <span>{new Date(email.createdAt).toLocaleDateString(language === 'id' ? 'id-ID' : 'en-US')}</span>
                              </span>
                            </div>
                          </div>
                          <div className="flex items-center gap-1 sm:gap-2 flex-shrink-0 w-full sm:w-auto">
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => copyToClipboard(email.fullEmail, email.id)}
                              className="flex-1 sm:flex-none text-xs sm:text-sm h-8 sm:h-9"
                            >
                              {copiedId === email.id ? (
                                <Check className="w-3 sm:w-4 h-3 sm:h-4 text-green-500" />
                              ) : (
                                <Copy className="w-3 sm:w-4 h-3 sm:h-4" />
                              )}
                            </Button>
                            <Button
                              variant="destructive"
                              size="sm"
                              onClick={() => deleteEmailRouting(email.id, email.ruleId)}
                              disabled={isLoading}
                              className="flex-1 sm:flex-none text-xs sm:text-sm h-8 sm:h-9"
                            >
                              <Trash2 className="w-3 sm:w-4 h-3 sm:h-4" />
                            </Button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Sidebar */}
          <div className="space-y-3 sm:space-y-4">
            {/* Stats Card */}
            <Card className="bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700">
              <CardHeader className="p-3 sm:p-4">
                <CardTitle className="text-base sm:text-lg text-slate-900 dark:text-white">{t("Statistik", language)}</CardTitle>
              </CardHeader>
              <CardContent className="p-3 sm:p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs sm:text-sm text-slate-600 dark:text-slate-400">{t("Total Email", language)}</span>
                  <span className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
                    {emailList.length}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs sm:text-sm text-slate-600 dark:text-slate-400">{t("Domain Aktif", language)}</span>
                  <span className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
                    {zones.length}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs sm:text-sm text-slate-600 dark:text-slate-400">{t("Email Aktif", language)}</span>
                  <span className="text-xl sm:text-2xl font-bold text-green-500">
                    {emailList.filter(e => e.isActive).length}
                  </span>
                </div>
              </CardContent>
            </Card>

            {/* Info Card */}
            <Card className="bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 border-blue-200 dark:border-blue-800">
              <CardHeader className="p-3 sm:p-4">
                <div className="flex items-center space-x-2">
                  <Shield className="w-4 sm:w-5 h-4 sm:h-5 text-blue-500 flex-shrink-0" />
                  <CardTitle className="text-base sm:text-lg text-slate-900 dark:text-white">{t("Keamanan", language)}</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="p-3 sm:p-4">
                <div className="space-y-1.5 text-xs sm:text-sm text-slate-700 dark:text-slate-300">
                  <p>• {t("API Token disimpan dengan aman", language)}</p>
                  <p>• {t("Tidak ada data yang di-hardcode", language)}</p>
                  <p>• {t("Koneksi HTTPS terenkripsi", language)}</p>
                  <p>• {t("Validasi input otomatis", language)}</p>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}