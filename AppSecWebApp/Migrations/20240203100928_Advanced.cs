using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AppSecWebApp.Migrations
{
    public partial class Advanced : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "SessionId",
                table: "AspNetUsers",
                newName: "PasswordHashHistory");

            migrationBuilder.AddColumn<DateTime>(
                name: "PasswordChangedDate",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PasswordChangedDate",
                table: "AspNetUsers");

            migrationBuilder.RenameColumn(
                name: "PasswordHashHistory",
                table: "AspNetUsers",
                newName: "SessionId");
        }
    }
}
