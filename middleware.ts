import { NextRequest, NextResponse } from "next/server";
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-in-production";

// Public paths that don't require authentication
const publicPaths = [
  "/auth/login",
  "/api/auth/login",
  "/api/auth/logout",
];

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Allow public paths
  if (publicPaths.some(path => pathname.startsWith(path))) {
    return NextResponse.next();
  }

  // Check for auth token in cookies
  const token = request.cookies.get("auth_token")?.value;

  if (!token) {
    // No token, redirect to login
    const loginUrl = new URL("/auth/login", request.url);
    return NextResponse.redirect(loginUrl);
  }

  try {
    // Verify JWT token
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    
    // Check if token is still valid based on remember me
    if (decoded.rememberMe) {
      // For remember me tokens, check if less than 1 day old
      const tokenAge = Date.now() / 1000 - decoded.iat; // age in seconds
      if (tokenAge > 24 * 60 * 60) { // more than 1 day
        throw new Error("Token expired");
      }
    } else {
      // For session tokens, check if less than 1 hour old
      const tokenAge = Date.now() / 1000 - decoded.iat; // age in seconds
      if (tokenAge > 60 * 60) { // more than 1 hour
        throw new Error("Token expired");
      }
    }

    // Token is valid, continue
    return NextResponse.next();
  } catch (error) {
    console.error("Middleware auth error:", error);
    // Invalid token, redirect to login
    const loginUrl = new URL("/auth/login", request.url);
    return NextResponse.redirect(loginUrl);
  }
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    "/((?!api|_next/static|_next/image|favicon.ico).*)",
  ],
};