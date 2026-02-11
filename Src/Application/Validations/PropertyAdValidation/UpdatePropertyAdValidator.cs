using Application.Dtos.PropertyAdDtos;
using FluentValidation;

namespace Application.Validations.PropertyAdValidation;

public class UpdatePropertyAdValidator:AbstractValidator<UpdatePropertyAdRequest>
{
    public UpdatePropertyAdValidator()
    {
        
        RuleFor(x => x.Id)
            .GreaterThan(0).WithMessage("Id 0-dan böyük olmalıdır.");

        When(x => x.Description is not null, () =>
        {
            RuleFor(x => x.Description!)
                .NotEmpty().WithMessage("Description boş string ola bilməz.")
                .MaximumLength(4000).WithMessage("Description maksimum 4000 simvol ola bilər.");
        });

        When(x => x.Price.HasValue, () =>
        {
            RuleFor(x => x.Price!.Value)
                .GreaterThan(0).WithMessage("Price 0-dan böyük olmalıdır.")
                .ScalePrecision(2, 18).WithMessage("Price ən çox 2 kəsr rəqəmi ola bilər.");
        });

        When(x => x.FloorNumber.HasValue, () =>
        {
            RuleFor(x => x.FloorNumber!.Value)
                .GreaterThanOrEqualTo(0).WithMessage("FloorNumber 0 və ya daha böyük olmalıdır.");
        });


        When(x => x.TotalFloors.HasValue, () =>
        {
            RuleFor(x => x.TotalFloors!.Value)
                .GreaterThan(0).WithMessage("TotalFloors 0-dan böyük olmalıdır.");
        });

        When(x => x.FloorNumber.HasValue && x.TotalFloors.HasValue, () =>
        {
            RuleFor(x => x.FloorNumber!.Value)
                .LessThanOrEqualTo(x => x.TotalFloors!.Value)
                .WithMessage("FloorNumber, TotalFloors-dan böyük ola bilməz.");
        });
    }
}
