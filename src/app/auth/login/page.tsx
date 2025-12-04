"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { LanguageSelector } from "@/components/language-selector";
import {
  Eye,
  EyeOff,
  User,
  Lock,
  AlertCircle,
  Shield,
  Mail,
} from "lucide-react";
import { toast } from "sonner";
import { Language, t } from "@/lib/translations";

export default function LoginPage() {
  const [language, setLanguage] = useState<Language>("id");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const router = useRouter();

  // Check if user is already logged in
  useEffect(() => {
    const savedAuth = localStorage.getItem("auth_token");
    const savedRemember = localStorage.getItem("remember_me");
    
    if (savedAuth && savedRemember === "true") {
      // User is remembered, redirect to main app
      router.push("/");
    }
    
    // Load language preference
    const savedLang = localStorage.getItem("language") as Language;
    if (savedLang) setLanguage(savedLang);
  }, [router]);

  const handleLanguageChange = (lang: Language) => {
    setLanguage(lang);
    localStorage.setItem("language", lang);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!username || !password) {
      setError(t("Username dan password harus diisi", language));
      return;
    }

    setIsLoading(true);
    setError("");

    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username,
          password,
          rememberMe,
        }),
      });

      const data = await response.json();

      if (data.success) {
        // Save authentication data
        localStorage.setItem("auth_token", data.token);
        localStorage.setItem("user_info", JSON.stringify(data.user));
        localStorage.setItem("remember_me", rememberMe.toString());
        
        // Set cookie expiration for remember me
        if (rememberMe) {
          const expires = new Date();
          expires.setDate(expires.getDate() + 1); // 1 day
          document.cookie = `auth_token=${data.token}; expires=${expires.toUTCString()}; path=/`;
        } else {
          // Session cookie (expires when browser closes)
          document.cookie = `auth_token=${data.token}; path=/`;
        }

        toast.success(t("Login berhasil!", language));
        router.push("/");
      } else {
        setError(data.error || t("Login gagal", language));
      }
    } catch (error) {
      console.error("Login error:", error);
      setError(t("Terjadi kesalahan, silakan coba lagi", language));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-slate-900 dark:to-slate-800 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Language Selector */}
        <div className="flex justify-end mb-4">
          <LanguageSelector 
            currentLanguage={language}
            onLanguageChange={handleLanguageChange}
          />
        </div>

        {/* Login Card */}
        <Card className="bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 shadow-lg">
          <CardHeader className="text-center pb-4">
            <div className="mx-auto w-16 h-16 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-full flex items-center justify-center mb-4">
              <Shield className="w-8 h-8 text-white" />
            </div>
            <CardTitle className="text-2xl font-bold text-slate-900 dark:text-white">
              {t("Login", language)}
            </CardTitle>
            <CardDescription className="text-slate-600 dark:text-slate-400">
              {t("Masuk untuk mengakses Email Routing Manager", language)}
            </CardDescription>
          </CardHeader>

          <CardContent className="pt-4">
            <form onSubmit={handleSubmit} className="space-y-4">
              {error && (
                <Alert variant="destructive" className="mb-4">
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              {/* Username Field */}
              <div className="space-y-2">
                <Label htmlFor="username" className="text-sm font-medium text-slate-700 dark:text-slate-300">
                  <User className="w-4 h-4 inline mr-2" />
                  {t("Username", language)}
                </Label>
                <Input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder={t("Masukkan username", language)}
                  className="w-full"
                  disabled={isLoading}
                  autoComplete="username"
                />
              </div>

              {/* Password Field */}
              <div className="space-y-2">
                <Label htmlFor="password" className="text-sm font-medium text-slate-700 dark:text-slate-300">
                  <Lock className="w-4 h-4 inline mr-2" />
                  {t("Password", language)}
                </Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={t("Masukkan password", language)}
                    className="w-full pr-10"
                    disabled={isLoading}
                    autoComplete="current-password"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                    onClick={() => setShowPassword(!showPassword)}
                    disabled={isLoading}
                  >
                    {showPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>

              {/* Remember Me Checkbox */}
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="remember"
                  checked={rememberMe}
                  onCheckedChange={setRememberMe}
                  disabled={isLoading}
                />
                <Label
                  htmlFor="remember"
                  className="text-sm text-slate-700 dark:text-slate-300 cursor-pointer"
                >
                  {t("Ingatkan saya selama 1 hari", language)}
                </Label>
              </div>

              {/* Submit Button */}
              <Button
                type="submit"
                className="w-full bg-gradient-to-r from-blue-500 to-indigo-600 hover:from-blue-600 hover:to-indigo-700 text-white"
                disabled={isLoading}
              >
                {isLoading ? (
                  <div className="flex items-center">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    {t("Sedang login...", language)}
                  </div>
                ) : (
                  <div className="flex items-center">
                    <Shield className="w-4 h-4 mr-2" />
                    {t("Login", language)}
                  </div>
                )}
              </Button>
            </form>

            {/* Security Info */}
            <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
              <div className="flex items-start space-x-2">
                <Mail className="w-4 h-4 text-blue-500 flex-shrink-0 mt-0.5" />
                <div className="text-xs text-blue-700 dark:text-blue-300">
                  <p className="font-semibold mb-1">{t("Informasi Keamanan", language)}:</p>
                  <ul className="space-y-1 text-xs">
                    <li>• {t("Gunakan password yang kuat dan unik", language)}</li>
                    <li>• {t("Jangan bagikan kredensial Anda", language)}</li>
                    <li>• {t("Fitur 'Ingatkan saya' berlaku 1 hari", language)}</li>
                  </ul>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Footer */}
        <div className="text-center mt-6 text-xs text-slate-500 dark:text-slate-400">
          <p>{t("Email Routing Manager - Aman & Terpercaya", language)}</p>
        </div>
      </div>
    </div>
  );
}