using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Persistence.Migrations
{
    /// <inheritdoc />
    public partial class ConfigurationsAdded : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_PropertyMedias_PropertyAds_PropertyAdId",
                table: "PropertyMedias");

            migrationBuilder.DropPrimaryKey(
                name: "PK_PropertyMedias",
                table: "PropertyMedias");

            migrationBuilder.DropPrimaryKey(
                name: "PK_PropertyAds",
                table: "PropertyAds");

            migrationBuilder.RenameTable(
                name: "PropertyMedias",
                newName: "PropertyMedia");

            migrationBuilder.RenameTable(
                name: "PropertyAds",
                newName: "PropertyAd");

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
                oldType: "int");

            migrationBuilder.AlterColumn<string>(
                name: "MediaUrl",
                table: "PropertyMedia",
                type: "nvarchar(500)",
                maxLength: 500,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AlterColumn<string>(
                name: "MediaType",
                table: "PropertyMedia",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AlterColumn<string>(
                name: "Title",
                table: "PropertyAd",
                type: "nvarchar(150)",
                maxLength: 150,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AlterColumn<decimal>(
                name: "Price",
                table: "PropertyAd",
                type: "decimal(18,2)",
                nullable: false,
                oldClrType: typeof(double),
                oldType: "float");

            migrationBuilder.AlterColumn<string>(
                name: "Location",
                table: "PropertyAd",
                type: "nvarchar(300)",
                maxLength: 300,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AlterColumn<string>(
                name: "Description",
                table: "PropertyAd",
                type: "nvarchar(4000)",
                maxLength: 4000,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AlterColumn<decimal>(
                name: "AreaInSquareMeters",
                table: "PropertyAd",
                type: "decimal(10,2)",
                nullable: false,
                oldClrType: typeof(double),
                oldType: "float");

            migrationBuilder.AddPrimaryKey(
                name: "PK_PropertyMedia",
                table: "PropertyMedia",
                column: "Id");

            migrationBuilder.AddPrimaryKey(
                name: "PK_PropertyAd",
                table: "PropertyAd",
                column: "Id");

            migrationBuilder.CreateIndex(
                name: "IX_PropertyMedia_PropertyAdId_Order",
                table: "PropertyMedia",
                columns: new[] { "PropertyAdId", "Order" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_PropertyAd_OfferType",
                table: "PropertyAd",
                column: "OfferType");

            migrationBuilder.CreateIndex(
                name: "IX_PropertyAd_Price",
                table: "PropertyAd",
                column: "Price");

            migrationBuilder.CreateIndex(
                name: "IX_PropertyAd_PropertyCategory",
                table: "PropertyAd",
                column: "PropertyCategory");

            migrationBuilder.CreateIndex(
                name: "IX_PropertyAd_RoomCount",
                table: "PropertyAd",
                column: "RoomCount");

            migrationBuilder.AddForeignKey(
                name: "FK_PropertyMedia_PropertyAd_PropertyAdId",
                table: "PropertyMedia",
                column: "PropertyAdId",
                principalTable: "PropertyAd",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
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

            migrationBuilder.DropPrimaryKey(
                name: "PK_PropertyAd",
                table: "PropertyAd");

            migrationBuilder.DropIndex(
                name: "IX_PropertyAd_OfferType",
                table: "PropertyAd");

            migrationBuilder.DropIndex(
                name: "IX_PropertyAd_Price",
                table: "PropertyAd");

            migrationBuilder.DropIndex(
                name: "IX_PropertyAd_PropertyCategory",
                table: "PropertyAd");

            migrationBuilder.DropIndex(
                name: "IX_PropertyAd_RoomCount",
                table: "PropertyAd");

            migrationBuilder.RenameTable(
                name: "PropertyMedia",
                newName: "PropertyMedias");

            migrationBuilder.RenameTable(
                name: "PropertyAd",
                newName: "PropertyAds");

            migrationBuilder.RenameIndex(
                name: "IX_PropertyMedia_PropertyAdId",
                table: "PropertyMedias",
                newName: "IX_PropertyMedias_PropertyAdId");

            migrationBuilder.AlterColumn<int>(
                name: "Order",
                table: "PropertyMedias",
                type: "int",
                nullable: false,
                oldClrType: typeof(int),
                oldType: "int",
                oldDefaultValue: 1);

            migrationBuilder.AlterColumn<string>(
                name: "MediaUrl",
                table: "PropertyMedias",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(500)",
                oldMaxLength: 500);

            migrationBuilder.AlterColumn<string>(
                name: "MediaType",
                table: "PropertyMedias",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(50)",
                oldMaxLength: 50);

            migrationBuilder.AlterColumn<string>(
                name: "Title",
                table: "PropertyAds",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(150)",
                oldMaxLength: 150);

            migrationBuilder.AlterColumn<double>(
                name: "Price",
                table: "PropertyAds",
                type: "float",
                nullable: false,
                oldClrType: typeof(decimal),
                oldType: "decimal(18,2)");

            migrationBuilder.AlterColumn<string>(
                name: "Location",
                table: "PropertyAds",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(300)",
                oldMaxLength: 300);

            migrationBuilder.AlterColumn<string>(
                name: "Description",
                table: "PropertyAds",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(4000)",
                oldMaxLength: 4000);

            migrationBuilder.AlterColumn<double>(
                name: "AreaInSquareMeters",
                table: "PropertyAds",
                type: "float",
                nullable: false,
                oldClrType: typeof(decimal),
                oldType: "decimal(10,2)");

            migrationBuilder.AddPrimaryKey(
                name: "PK_PropertyMedias",
                table: "PropertyMedias",
                column: "Id");

            migrationBuilder.AddPrimaryKey(
                name: "PK_PropertyAds",
                table: "PropertyAds",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_PropertyMedias_PropertyAds_PropertyAdId",
                table: "PropertyMedias",
                column: "PropertyAdId",
                principalTable: "PropertyAds",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
