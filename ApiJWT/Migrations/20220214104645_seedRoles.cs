using ApiJWT.Helpers;
using Microsoft.EntityFrameworkCore.Migrations;
using System;

namespace ApiJWT.Migrations
{
    public partial class seedRoles : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns:new[] {"Id","Name", "NormalizedName", "ConcurrencyStamp" },
                values: new object[] {Guid.NewGuid().ToString(), UsersRoles.User, UsersRoles.User.ToUpper(), Guid.NewGuid().ToString() }
                );

            migrationBuilder.InsertData(
    table: "AspNetRoles",
    columns: new[] { "Id", "Name", "NormalizedName", "ConcurrencyStamp" },
    values: new object[] { Guid.NewGuid().ToString(), UsersRoles.Admin, UsersRoles.Admin.ToUpper(), Guid.NewGuid().ToString() }
    );
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DELETE FROM [AspNetRoles] ");
        }
    }
}
