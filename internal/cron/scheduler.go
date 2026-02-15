package cron

import (
	"fmt"
	"time"

	"github.com/nijatsdev/go-jwt-auth/internal/logger"
	"github.com/nijatsdev/go-jwt-auth/internal/store"

	"github.com/go-co-op/gocron/v2"
)

type Scheduler struct {
	logger               *logger.Logger
	refreshTokenStore    store.RefreshTokenStore
	scheduler            gocron.Scheduler
	expiredRetentionDays int
	revokedRetentionDays int
}

func NewScheduler(
	logger *logger.Logger,
	refreshTokenStore store.RefreshTokenStore,
	ExpiredRetentionDays int,
	RevokedRetentionDays int,
) (*Scheduler, error) {
	timeLocation, err := time.LoadLocation("Local")
	if err != nil {
		return nil, err
	}

	// Create scheduler with location (for scheduling at specific times)
	scheduler, err := gocron.NewScheduler(
		gocron.WithLocation(timeLocation),
	)

	if err != nil {
		return nil, err
	}

	return &Scheduler{
		logger:               logger,
		refreshTokenStore:    refreshTokenStore,
		scheduler:            scheduler,
		expiredRetentionDays: ExpiredRetentionDays,
		revokedRetentionDays: RevokedRetentionDays,
	}, nil
}

// Start begins the scheduler
func (s *Scheduler) Start() error {
	// Schedule cleanup job
	cleanupJob, err := s.ScheduleCleanup()
	if err != nil {
		return err
	}

	// Start the scheduler
	s.scheduler.Start()

	cleanupJobNextRun, err := cleanupJob.NextRun()
	if err != nil {
		return err
	}

	s.logger.Info().
		Interface("jobs", map[string]string{
			"name":     cleanupJob.Name(),
			"next_run": cleanupJobNextRun.Format(time.RFC3339),
		}).
		Msg("Scheduler started")
	return nil
}

// ScheduleCleanup sets up the daily cleanup job
func (s *Scheduler) ScheduleCleanup() (gocron.Job, error) {
	// Schedule daily cleanup at 2 AM
	job, err := s.scheduler.NewJob(
		gocron.DailyJob(
			1,
			gocron.NewAtTimes(
				gocron.NewAtTime(2, 0, 0), // 2:00 AM
			),
		),
		gocron.NewTask(
			func() {
				s.runCleanup()
			},
		),
		gocron.WithName("refresh_token_cleanup"),
	)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to schedule cleanup job")
		return nil, err
	}

	return job, nil
}

// runCleanup performs the cleanup of expired and revoked tokens
func (s *Scheduler) runCleanup() {
	s.logger.Info().Msg("Running scheduled token cleanup")

	startTime := time.Now()

	tokensDeleted, err := s.refreshTokenStore.CleanupExpired(
		s.expiredRetentionDays,
		s.revokedRetentionDays,
	)
	if err != nil {
		return
	}

	duration := time.Since(startTime).Seconds()

	jobs := s.scheduler.Jobs()
	if len(jobs) == 0 {
		s.logger.Error().Msg("No jobs found in scheduler")
		return
	}

	nextRun, err := jobs[0].NextRun()
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("Failed to get next run time")
		return
	}

	s.logger.Info().
		Int64("tokens_deleted", tokensDeleted).
		Float64("duration", duration).
		Str("next_run", nextRun.Format(time.RFC3339)).
		Msg("Token cleanup completed successfully")
}

// Shutdown stops the scheduler
func (s *Scheduler) Shutdown() error {
	s.logger.Info().Msg("Stopping scheduler")

	if err := s.scheduler.Shutdown(); err != nil {
		return fmt.Errorf("failed to stop scheduler: %w", err)
	}

	return nil
}
