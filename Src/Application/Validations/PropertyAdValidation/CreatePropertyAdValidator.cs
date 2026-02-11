using Application.Dtos.PropertyAdDtos;
using FluentValidation;

namespace Application.Validations.PropertyAdValidation;

public class CreatePropertyAdValidator : AbstractValidator<CreatePropertyAdRequest>
{
    public CreatePropertyAdValidator()
    {

        RuleFor(x => x.Title)
            .NotEmpty().WithMessage("Title boş ola bilməz.")
            .MaximumLength(150).WithMessage("Title maksimum 150 simvol ola bilər.");

        RuleFor(x => x.Description)
                .NotEmpty().WithMessage("Description boş ola bilməz.")
                .MaximumLength(4000).WithMessage("Description maksimum 4000 simvol ola bilər.");


        RuleFor(x => x.Price)
                .GreaterThan(0).WithMessage("Price 0-dan böyük olmalıdır.")
                .Must(HaveMaxTwoDecimalPlaces).WithMessage("Price ən çox 2 kəsr rəqəmi ola bilər.")
                .LessThanOrEqualTo(9999999999999999.99m).WithMessage("Price çox böyükdür.");

        RuleFor(x => x.IsNew)
                .NotNull().WithMessage("IsNew göndərilməlidir.");

        RuleFor(x => x.IsRenovated)
                .NotNull().WithMessage("IsRenovated göndərilməlidir.");

        RuleFor(x => x.IsMortgage)
                .NotNull().WithMessage("IsMortgage göndərilməlidir.");

        RuleFor(x => x.IsTitleDeedAvailable)
                .NotNull().WithMessage("IsTitleDeedAvailable göndərilməlidir.");

        RuleFor(x => x.RoomCount).NotEmpty()
                .GreaterThan(0).WithMessage("RoomCount 0-dan böyük olmalıdır.");

        RuleFor(x => x.AreaInSquareMeters)
                .GreaterThan(0).WithMessage("AreaInSquareMeters 0-dan böyük olmalıdır.")
                .Must(HaveMaxTwoDecimalPlaces).WithMessage("AreaInSquareMeters ən çox 2 kəsr rəqəmi ola bilər.")
                .LessThanOrEqualTo(99999999.99m).WithMessage("AreaInSquareMeters çox böyükdür.");

        RuleFor(x => x.Location)
                .NotEmpty().WithMessage("Location boş ola bilməz.")
                .MaximumLength(300).WithMessage("Location maksimum 300 simvol ola bilər.");

        RuleFor(x => x.FloorNumber)
                .GreaterThanOrEqualTo(0).WithMessage("FloorNumber 0 və ya daha böyük olmalıdır.");

        RuleFor(x => x.PropertyCategory)
                .IsInEnum().WithMessage("PropertyCategory düzgün deyil.");

        RuleFor(x => x.OfferType)
                .IsInEnum().WithMessage("OfferType düzgün deyil.");

    
     }
    private static bool HaveMaxTwoDecimalPlaces(decimal value)
    {

        return decimal.Round(value, 2) == value;
    }
}

