require "active_support/concern"

module Pundit
  module Resource
    extend ActiveSupport::Concern

    included do
      define_jsonapi_resources_callbacks :policy_authorize

      before_save :authorize_create_or_update
      before_remove :authorize_destroy
      after_create_to_many_link :authorize_can_create_to_many_link
      after_replace_to_many_links :authorize_can_replace_to_many_links
      after_replace_to_one_link :authorize_can_replace_to_one_link
      after_replace_polymorphic_to_one_link :authorize_can_replace_polymorphic_to_one_link
      after_remove_to_many_link :authorize_can_remove_to_many_link
      after_remove_to_one_link :authorize_can_remove_to_one_link
    end

    module ClassMethods
      def records(options = {})
        warn_if_show_defined

        context = options[:context]
        context[:policy_used]&.call
        Pundit.policy_scope!(pundit_user(context), _model_class)
      end

      def creatable_fields(context)
        policy = policy(context)
        if policy.respond_to? :permitted_attributes_for_create
          policy.permitted_attributes_for_create
        else
          policy.permitted_attributes
        end
      end

      def updatable_fields(context)
        policy = policy(context)
        if policy.respond_to? :permitted_attributes_for_update
          policy.permitted_attributes_for_update
        else
          policy.permitted_attributes
        end
      end

      private

      def policy(context)
        # Unfortunately, jsonapi-resources doesn't provide a record to use in
        # the policy at this point.  We will have to authorize based only on the
        # account and the model's class.
        Pundit.policy!(pundit_user(context), _model_class)
      end

      def pundit_user(context)
        context && context[:current_user]
      end

      def warn_if_show_defined
        policy_class = Pundit::PolicyFinder.new(_model_class.new).policy!
        if policy_class.instance_methods(false).include?(:show?)
          puts "WARN: pundit-resources does not use the show? action."
          puts "      #{policy_class::Scope} will be used instead."
        end
      end
    end

    def fetchable_fields
      if policy.respond_to? :permitted_attributes_for_show
        policy.permitted_attributes_for_show
      else
        policy.permitted_attributes
      end
    end

    # When authorizing operations on relationships, it is useful to know which
    # relationships and which records are being changed.  We capture the
    # arguments given to those methods here and then pass them on to the
    # policy.
    [
      :create_to_many_links,
      :remove_to_many_link,
      :remove_to_one_link,
      :replace_polymorphic_to_one_link,
      :replace_to_many_links,
      :replace_to_one_link,
    ].each do |m|
      define_method m do |*args|
        begin
          @link_operation_details = args
          super(*args)
        ensure
          @link_operation_details = nil
        end
      end
    end

    protected

    def can(method)
      run_callbacks :policy_authorize do
        context[:policy_used]&.call
        policy.public_send(method)
      end
    end

    def can_link(method)
      run_callbacks :policy_authorize do
        context[:policy_used]&.call
        if policy.respond_to?(method)
          policy.public_send(method, *@link_operation_details[1..-1])
        else
          false
        end
      end
    end

    def pundit_user
      self.class.pundit_user(context)
    end

    def policy
      Pundit.policy!(pundit_user, _model)
    end

    def authorize_create_or_update
      action = _model.new_record? ? :create : :update
      not_authorized!(action) unless can :"#{action}?"
    end

    def authorize_destroy
      not_authorized! :destroy unless can :destroy?
    end

    def authorize_can_create_to_many_link
      action = :"create_#{@link_operation_details[0]}_link"
      not_authorized!(action) unless can_link :"#{action}?"
    end

    def authorize_can_replace_to_many_links
      action = :"replace_#{@link_operation_details[0]}_links"
      not_authorized!(action) unless can_link :"#{action}?"
    end

    def authorize_can_replace_to_one_link
      action = :"replace_#{@link_operation_details[0]}_link"
      not_authorized!(action) unless can_link :"#{action}?"
    end

    def authorize_can_replace_polymorphic_to_one_link
      action = :"replace_#{@link_operation_details[0]}_link"
      not_authorized!(action) unless can_link :"#{action}?"
    end

    def authorize_can_remove_to_many_link
      action = :"remove_#{@link_operation_details[0]}_link"
      not_authorized!(action) unless can_link :"#{action}?"
    end

    def authorize_can_remove_to_one_link
      action = :"remove_#{@link_operation_details[0]}_link"
      not_authorized!(action) unless can_link :"#{action}?"
    end

    def records_for(association_name, options={})
      relationships = self.class._relationships.
        values.
        select { |r| r.relation_name(context: @context) == association_name }.
        uniq(&:class)

      unless relationships.count == 1
        raise "Can't infer relationship type for #{association_name}"
      end

      relationship = relationships.first

      case relationship
      when JSONAPI::Relationship::ToMany
        records = _model.public_send(association_name)
        policy_scope = Pundit.policy_scope!(
          pundit_user,
          records
        )
        records.merge(policy_scope)
      when JSONAPI::Relationship::ToOne
        record = _model.public_send(association_name)

        # Don't rely on policy.show? being defined since it isn't used for
        # show actions directly and should always have the same behaviour.
        if record && show?(Pundit.policy!(pundit_user, record), record.id)
          record
        else
          nil
        end
      end
    end

    private

    def not_authorized!(action)
      options = { query: action, record: _model, policy: policy }
      raise Pundit::NotAuthorizedError, options
    end

    def show?(policy, record_id)
      policy.scope.where(id: record_id).exists?
    end
  end
end
