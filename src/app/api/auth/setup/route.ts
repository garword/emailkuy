import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import bcrypt from "bcryptjs";

export async function POST(request: NextRequest) {
  try {
    // Create default user if it doesn't exist
    const existingUser = await db.users.findUnique({
      where: { username: "admin" }
    });

    if (existingUser) {
      return NextResponse.json({
        success: false,
        error: "Default user already exists"
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash("admin123", 10);

    // Create default user
    const user = await db.users.create({
      data: {
        username: "admin",
        password: hashedPassword,
        email: "admin@emailkuy.com",
        name: "Administrator",
        isActive: true
      }
    });

    return NextResponse.json({
      success: true,
      message: "Default user created successfully",
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        name: user.name,
        isActive: user.isActive
      }
    });

  } catch (error) {
    console.error("Create user error:", error);
    return NextResponse.json(
      { success: false, error: "Failed to create user" },
      { status: 500 }
    );
  }
}
