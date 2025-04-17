using AutoGenerator.Conditions;
using LAHJAAPI.Models;
using LAHJAAPI.V1.Validators.Conditions;
using V1.DyModels.Dso.Requests;
using V1.DyModels.Dso.ResponseFilters;


namespace LAHJAAPI.V1.Validators
{



    public enum ModelGatewayValidatorStates
    {
        IsValid,
        IsFull,
        HasName,
        HasUrl,
        HasToken,
        IsDefault
    }

    public class ModelGatewayValidator : BaseValidator<ModelGateway, ModelGatewayValidatorStates>, ITValidator
    {
        private readonly IConditionChecker _checker;

        public ModelGatewayValidator(IConditionChecker checker) : base(checker)
        {
            _checker = checker;
        }

        protected override void InitializeConditions()
        {
            _provider.Register(
                ModelGatewayValidatorStates.HasName,
                new LambdaCondition<ModelGateway>(
                    nameof(ModelGatewayValidatorStates.HasName),
                    context => !string.IsNullOrWhiteSpace(context.Name),
                    "Name is required"
                )
            );

            _provider.Register(
                ModelGatewayValidatorStates.HasUrl,
                new LambdaCondition<ModelGateway>(
                    nameof(ModelGatewayValidatorStates.HasUrl),
                    context => !string.IsNullOrWhiteSpace(context.Url),
                    "URL is required"
                )
            );

            _provider.Register(
                ModelGatewayValidatorStates.HasToken,
                new LambdaCondition<ModelGateway>(
                    nameof(ModelGatewayValidatorStates.HasToken),
                    context => !string.IsNullOrWhiteSpace(context.Token),
                    "Token is required"
                )
            );

            _provider.Register(
                ModelGatewayValidatorStates.IsDefault,
                new LambdaCondition<ModelGateway>(
                    nameof(ModelGatewayValidatorStates.IsDefault),
                    context => context.IsDefault,
                    "Model must be default"
                )
            );

            _provider.Register(
                ModelGatewayValidatorStates.IsFull,
                new LambdaCondition<ModelGateway>(
                    nameof(ModelGatewayValidatorStates.IsFull),
                    context =>
                        !string.IsNullOrWhiteSpace(context.Name) &&
                        !string.IsNullOrWhiteSpace(context.Url),
                    "Name and URL are required"
                )
            );
        }
    }


}