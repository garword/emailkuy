import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { serialize } from "cookie";

// JWT Secret (should be in environment variables in production)
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-in-production";

export async function POST(request: NextRequest) {
  try {
    const { username, password, rememberMe } = await request.json();

    // Validate input
    if (!username || !password) {
      return NextResponse.json(
        { success: false, error: "Username dan password harus diisi" },
        { status: 400 }
      );
    }

    // Find user in database
    const user = await db.users.findUnique({
      where: { username }
    });

    if (!user) {
      return NextResponse.json(
        { success: false, error: "Username atau password salah" },
        { status: 401 }
      );
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return NextResponse.json(
        { success: false, error: "Username atau password salah" },
        { status: 401 }
      );
    }

    // Check if user is active
    if (!user.isActive) {
      return NextResponse.json(
        { success: false, error: "Akun Anda tidak aktif" },
        { status: 401 }
      );
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user.id, 
        username: user.username,
        rememberMe: rememberMe || false 
      },
      JWT_SECRET,
      { 
        expiresIn: rememberMe ? '1d' : '1h' // 1 day if remember me, 1 hour if not
      }
    );

    // Set cookie with appropriate expiration
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax' as const,
      path: '/',
    };

    let cookieValue = `auth_token=${token}`;
    
    if (rememberMe) {
      // Add expiration for remember me (1 day)
      const expires = new Date();
      expires.setDate(expires.getDate() + 1);
      cookieValue += `; Expires=${expires.toUTCString()}`;
    }
    
    const cookie = serialize('auth_token', token, cookieOptions);

    // Prepare user data for response (exclude password)
    const { password: _, ...userWithoutPassword } = user;

    const response = NextResponse.json({
      success: true,
      message: "Login berhasil",
      token,
      user: userWithoutPassword
    });

    // Set cookie in response
    response.headers.set('Set-Cookie', cookie);

    return response;

  } catch (error) {
    console.error("Login error:", error);
    return NextResponse.json(
      { success: false, error: "Terjadi kesalahan server" },
      { status: 500 }
    );
  }
}