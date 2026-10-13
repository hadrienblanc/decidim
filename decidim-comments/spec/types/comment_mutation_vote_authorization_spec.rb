# frozen_string_literal: true

require "spec_helper"
require "decidim/api/test"
require "decidim/proposals/test/factories"

module Decidim
  module Api
    describe MutationType do
      include_context "with a graphql class type"

      # Security regression test (broken access control, CVE-2026-40870 class).
      #
      # The `comment(id:) { upVote }` / `downVote` GraphQL mutations must not
      # offer a weaker authorization policy than the equivalent HTML endpoint
      # (Decidim::Comments::VotesController#create), which enforces
      # `enforce_permission_to(:vote, :comment, comment:)` before calling the
      # very same Decidim::Comments::VoteComment command.
      #
      # CommentMutationType#up_vote / #down_vote
      # (decidim-comments/lib/decidim/api/comment_mutation_type.rb) invoke
      # VoteComment without any `allowed_to?(:vote, :comment)` check. The
      # generic GraphQL object guard (GraphqlPermissions) only checks
      # `:read` on the participatory space and the component, which passes for
      # any published open space even when comment votes are disabled on the
      # component: the vote is persisted although the permission system — and
      # therefore the HTML endpoint — denies it.
      describe "comment upVote/downVote authorization" do
        context "when comment votes are disabled on the component of a published open space" do
          let!(:process) { create(:participatory_process, :published, organization: current_organization) }
          let!(:component) { create(:proposal_component, participatory_space: process) }
          let!(:proposal) { create(:proposal, component:) }
          let!(:comment) { create(:comment, commentable: proposal, root_commentable: proposal) }

          # An admin turns comments (and therefore comment votes) off after the
          # discussion existed — the comment and its votes remain readable.
          before do
            raw = component[:settings]
            raw["global"]["comments_enabled"] = false
            component.update_column(:settings, raw)
          end

          # Policy anchor: this is the exact permission enforced by
          # Decidim::Comments::VotesController#create. The HTML endpoint
          # refuses this vote.
          it "denies the :vote, :comment permission" do
            permission_action = Decidim::PermissionAction.new(scope: :public, action: :vote, subject: :comment)
            permissions = Decidim::Comments::Permissions.new(current_user, permission_action, { comment: }).permissions

            expect(proposal.reload.accepts_new_comments?).to be false
            expect(permissions.allowed?).to be false
          end

          it "does not persist an upVote" do
            result = run_mutation("upVote")

            expect(comment.reload.up_votes.count).to eq(0), <<~MSG
              The GraphQL `upVote` mutation persisted a vote for user #{current_user.id} on comment \
              #{comment.id} of proposal #{proposal.id} while comment votes are disabled on the \
              component and Decidim::Comments::Permissions denies the :vote, :comment action to \
              this user. The API answered: #{result.to_json}
            MSG
            expect(comment.up_votes.map(&:author)).not_to include(current_user)
          end

          it "does not persist a downVote" do
            result = run_mutation("downVote")

            expect(comment.reload.down_votes.count).to eq(0), <<~MSG
              The GraphQL `downVote` mutation persisted a vote for user #{current_user.id} on comment \
              #{comment.id} of proposal #{proposal.id} while comment votes are disabled on the \
              component and Decidim::Comments::Permissions denies the :vote, :comment action to \
              this user. The API answered: #{result.to_json}
            MSG
            expect(comment.down_votes.map(&:author)).not_to include(current_user)
          end
        end

        # Boundary of the finding, kept as a regression guard: for comments of
        # *restricted* participatory spaces, the generic object-level guard
        # (GraphqlPermissions.authorized? checks :read on the comment's
        # participatory_space) rejects the mutation entry itself, so a
        # non-member cannot reach the upVote/downVote resolvers.
        context "when the comment belongs to a restricted participatory space" do
          let!(:process) { create(:participatory_process, :published, :restricted, organization: current_organization) }
          let!(:component) { create(:dummy_component, participatory_space: process) }
          let!(:commentable) { create(:dummy_resource, component:) }
          let!(:comment) { create(:comment, commentable:) }

          it "denies the :vote, :comment permission to a non-member" do
            permission_action = Decidim::PermissionAction.new(scope: :public, action: :vote, subject: :comment)
            permissions = Decidim::Comments::Permissions.new(current_user, permission_action, { comment: }).permissions

            expect(permissions.allowed?).to be false
          end

          it "does not persist an upVote for a non-member" do
            run_mutation("upVote")

            expect(comment.reload.up_votes.count).to eq(0)
          end
        end

        private

        # Runs the mutation. Tolerates errors raised while authorizing the
        # *return type* (CommentType.authorized? may raise UnauthorizedObjectError
        # after the vote has already been persisted): the database is the
        # reliable oracle here. Any other error is a test bug and must surface.
        def run_mutation(field)
          mutation = %(mutation { comment(id: "#{comment.id}") { #{field} { id } } })
          schema.execute(mutation, context: graphql_context)
        rescue Decidim::Api::Errors::UnauthorizedObjectError,
               Decidim::Api::Errors::UnauthorizedFieldError,
               Decidim::Api::Errors::PermissionNotSetError
          nil
        end

        def graphql_context
          {
            current_organization:,
            current_user:,
            current_component:,
            scopes: api_scopes,
            can_introspect:
          }
        end
      end
    end
  end
end
