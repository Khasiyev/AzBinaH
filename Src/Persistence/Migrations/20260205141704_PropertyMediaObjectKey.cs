using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Persistence.Migrations
{
    /// <inheritdoc />
    public partial class PropertyMediaObjectKey : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_PropertyMedia_PropertyAd_PropertyAdId",
                table: "PropertyMedia");

            migrationBuilder.DropPrimaryKey(
                name: "PK_PropertyMedia",
                table: "PropertyMedia");

            migrationBuilder.DropIndex(
                name: "IX_PropertyMedia_PropertyAdId_Order",
                table: "PropertyMedia");

            migrationBuilder.DropColumn(
                name: "MediaType",
                table: "PropertyMedia");

            migrationBuilder.RenameTable(
                name: "PropertyMedia",
                newName: "PropertyMedias");

            migrationBuilder.RenameColumn(
                name: "MediaUrl",
                table: "PropertyMedias",
                newName: "ObjectKey");

            migrationBuilder.RenameIndex(
                name: "IX_PropertyMedia_PropertyAdId",
                table: "PropertyMedias",
                newName: "IX_PropertyMedias_PropertyAdId");

            migrationBuilder.AlterColumn<int>(
                name: "Order",
                table: "PropertyMedias",
                type: "int",
                nullable: false,
                defaultValue: 1,
                oldClrType: typeof(int),
                oldType: "int",
                oldDefaultValue: 1);

            migrationBuilder.AddPrimaryKey(
                name: "PK_PropertyMedias",
                table: "PropertyMedias",
                column: "Id");

            migrationBuilder.CreateIndex(
                name: "IX_PropertyMedias_PropertyAdId_Order",
                table: "PropertyMedias",
                columns: new[] { "PropertyAdId", "Order" });

            migrationBuilder.AddForeignKey(
                name: "FK_PropertyMedias_PropertyAd_PropertyAdId",
                table: "PropertyMedias",
                column: "PropertyAdId",
                principalTable: "PropertyAd",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_PropertyMedias_PropertyAd_PropertyAdId",
                table: "PropertyMedias");

            migrationBuilder.DropPrimaryKey(
                name: "PK_PropertyMedias",
                table: "PropertyMedias");

            migrationBuilder.DropIndex(
                name: "IX_PropertyMedias_PropertyAdId_Order",
                table: "PropertyMedias");

            migrationBuilder.RenameTable(
                name: "PropertyMedias",
                newName: "PropertyMedia");

            migrationBuilder.RenameColumn(
                name: "ObjectKey",
                table: "PropertyMedia",
                newName: "MediaUrl");

            migrationBuilder.RenameIndex(
                name: "IX_PropertyMedias_PropertyAdId",
                table: "PropertyMedia",
                newName: "IX_PropertyMedia_PropertyAdId");

            migrationBuilder.AlterColumn<int>(
                name: "Order",
                table: "PropertyMedia",
                type: "int",
                nullable: false,
                defaultValue: 1,
                oldClrType: typeof(int),
                oldType: "int",
                oldDefaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "MediaType",
                table: "PropertyMedia",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddPrimaryKey(
                name: "PK_PropertyMedia",
                table: "PropertyMedia",
                column: "Id");

            migrationBuilder.CreateIndex(
                name: "IX_PropertyMedia_PropertyAdId_Order",
                table: "PropertyMedia",
                columns: new[] { "PropertyAdId", "Order" },
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_PropertyMedia_PropertyAd_PropertyAdId",
                table: "PropertyMedia",
                column: "PropertyAdId",
                principalTable: "PropertyAd",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
